# `@sinksight/library-hash` — Spécification technique

## Vue d'ensemble

`sinksight-library-hash` est un workspace Rust qui remplit deux rôles :

1. **Extraction** : parser un script JavaScript et retourner le set de tous les Library Hashes qu'il contient (hash du fichier entier + hash de chaque fonction éligible). Utilisé par le pipeline Node.js du repo `sinksight-library-db` pour construire la base de données publique.

2. **Vérification** : étant donné un script JavaScript et une base de données pré-chargée, identifier les portions du script qui correspondent à des librairies connues. Utilisé par l'extension VS Code de SinkSight pour filtrer les faux positifs.

Le workspace expose trois crates :

- **`core`** (rlib) : logique pure Rust, consommée par les deux targets ci-dessous
- **`wasm`** (cdylib) : bindings WebAssembly via `wasm-bindgen`, publié sur npm sous `@sinksight/library-hash`
- **`napi`** (cdylib) : bindings Node.js natifs via `napi-rs`, utilisé par `sinksight-library-db`

---

## Contexte : le problème à résoudre

SinkSight est un outil de détection de vulnérabilités DOM XSS. Il intercepte les scripts JavaScript chargés par un navigateur Firefox et les analyse côté VS Code avec des détecteurs basés sur Babel.

Le problème : des librairies connues et auditées (jQuery, React, Lodash...) génèrent de nombreux faux positifs. On veut les identifier pour exclure leurs findings de l'analyse.

Les scripts peuvent être :

- Des fichiers de lib non modifiés (CDN, téléchargement direct)
- Des fichiers de lib légèrement modifiés (reformatage, changement CRLF, commentaires ajoutés/supprimés)
- Des fichiers dont les variables locales ont été renommées (minification légère sans mangling structural)
- Des bundles (webpack, rollup, vite, esbuild, parcel, browserify) contenant un mélange de code de librairies et de code métier, éventuellement tree-shakés

Le hash doit être **basé sur l'AST** pour être invariant au formatage et aux commentaires, tout en étant **suffisamment précis** (incluant les valeurs des littéraux et les noms des références libres) pour identifier de manière fiable une lib spécifique.

Les scripts analysés par SinkSight sont **toujours du JavaScript directement exécutable dans un navigateur**. Aucun support JSX ou TypeScript n'est nécessaire.

---

## Format du hash

```txt
slh1-<sha256_hex>
```

- `slh1` : préfixe de version de l'algorithme. Incrémenté (`slh2`, `slh3`...) à chaque changement de l'algorithme qui rendrait les anciens hashes incompatibles.
- `-` : séparateur
- `<sha256_hex>` : 64 caractères hexadécimaux minuscules (SHA-256)

Exemples:

```txt
slh1-a3f2b8c91d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
slh1-0000000000000000000000000000000000000000000000000000000000000000
```

Le format est parsé avec un simple `split('-', 2)` -> `["slh1", "<hex>"]`.

Lors de la vérification, le module WASM **doit** vérifier que la version de l'algorithme des hashes dans la DB correspond à celle qu'il produit. En cas de mismatch -> erreur explicite.

---

## Algorithme de hashing — `slh1`

### Entrée

Un nœud AST JavaScript (racine `Program`, ou un nœud de type fonction/classe).

### Parsing

Le parser utilisé est **oxc** (`oxc_parser`). Les scripts analysés sont du JavaScript pur (ES2020+), aucun support JSX ou TypeScript n'est requis.

Configuration requise:
- **sourceType** : détection automatique `module` vs `script` selon la présence de `import`/`export` (équivalent du mode `"unambiguous"` de Babel)
- **Error recovery** : activé (les scripts capturés peuvent contenir du JS partiellement invalide)
- **Syntaxes acceptées** : class properties, class private properties/methods, dynamic import, object rest/spread, optional chaining, nullish coalescing, top-level await

### Analyse sémantique — classification des identifiants

Avant la traversée de hashing, une **analyse sémantique** (scopes et bindings) doit être effectuée sur l'AST. Cette analyse sert à classifier chaque référence à un `Identifier` comme :

- **Binding local** : variable déclarée dans le scope courant ou un scope ancêtre englobant la fonction hashée (paramètres de fonction, `var`/`let`/`const`, `catch` param, class name dans la class expression, `for...in`/`for...of` variable)
- **Référence libre** : tout identifiant qui référence un binding défini **en dehors** du sous-arbre hashé, ou un global implicite (`document`, `window`, `XMLHttpRequest`, `console`, etc.)

L'implémentation utilise `oxc_semantic` qui fournit les scopes et les bindings nativement.

**Normalisation des bindings locaux :**

Chaque scope maintient un **compteur de bindings** (démarrant à 0). Quand un binding local est **déclaré**, il se voit attribuer le prochain numéro séquentiel dans son scope. Quand ce binding est **référencé**, le token émis est `L<n>` (où `<n>` est le numéro attribué à la déclaration).

Exemple :
```javascript
// Original
function ajax(url, options) {
    var xhr = new XMLHttpRequest();
    xhr.open(options.method, url);
}
// Tokens : ...Identifier,L0, Identifier,L1, ...Identifier,L2, ...
//           (url=L0)     (options=L1)       (xhr=L2)

// Après renommage (minification légère)
function ajax(e, t) {
    var n = new XMLHttpRequest();
    n.open(t.method, e);
}
// Tokens : ...Identifier,L0, Identifier,L1, ...Identifier,L2, ...
//           (e=L0)       (t=L1)              (n=L2)

// -> MÊME hash ! Les références libres (XMLHttpRequest, .open, .method) sont préservées.
```

**Références libres :** le nom original est conservé tel quel dans le hash (avec le stripping des digits, voir ci-dessous). Cela inclut :
- Les globals du navigateur (`document`, `window`, `navigator`, `XMLHttpRequest`...)
- Les propriétés de member expressions (`obj.forEach`, `arr.length`)
- Les noms de fonctions lorsqu'ils référencent un binding externe

**Règle de scope pour le hashing de sous-arbres :** quand on hash une fonction individuelle (pas le Programme entier), les bindings sont relatifs au **sous-arbre hashé**. Un identifiant qui fait référence à un binding déclaré *dans* la fonction hashée est local ; un identifiant qui référence un binding déclaré *en dehors* (dans un scope parent, ou global) est une référence libre.

### Traversée

L'AST est traversé en **profondeur d'abord (DFS), pré-ordre**. Pour chaque nœud visité, des tokens sont ajoutés séquentiellement dans un buffer.

### Tokens collectés

Pour chaque nœud de l'AST, dans l'ordre de visite :

#### 1. Type du nœud
Toujours ajouté. Le nom du type doit correspondre aux types ESTree/oxc.

```
"FunctionDeclaration", "VariableDeclaration", "CallExpression", etc.
```

**Exception — hash de sous-arbre de fonction/classe :** quand l'algorithme `slh1` est appliqué à un nœud de type `FunctionDeclaration`, `FunctionExpression`, `ArrowFunctionExpression`, `ClassDeclaration` ou `ClassExpression` **en tant que racine du sous-arbre hashé** (c'est-à-dire via `extractHashes` ou `checkScript`), le token de type du nœud racine **n'est pas émis**. De même, le `id` (nom) de la fonction/classe racine **n'est pas émis**. Seuls les paramètres et le body sont inclus dans le hash.

Cette règle rend le hash invariant au nom et au type de la fonction, ce qui améliore la robustesse face aux minifiers et aux transformations de bundlers (`FunctionDeclaration` ↔ `FunctionExpression`, renommage de fonctions exportées).

Note : cette exception ne s'applique pas au hash du fichier entier (`Program`), où tous les types et noms sont inclus normalement.

#### 2. Identifiants

Pour les nœuds `Identifier` :
- Si c'est un **binding local** (déclaration ou référence) : émettre `L<n>` où `<n>` est le numéro séquentiel attribué dans le scope de déclaration
- Si c'est une **référence libre** : émettre le nom de l'identifiant, **avec les chiffres remplacés par la chaîne vide**

```javascript
// Les noms locaux sont normalisés :
// "url" -> "L0", "options" -> "L1", "xhr" -> "L2"  (peu importe le nom)

// Les noms libres gardent leur identité (digits strippés) :
// "XMLHttpRequest" -> "XMLHttpRequest"
// "identifier_42" -> "identifier_"
// "_0" -> "_"
```

La regex de stripping des digits pour les références libres : `name.replace(/[0-9]+/g, "")`

#### 3. Propriétés de MemberExpression non-computed
Pour un nœud `MemberExpression` dont `computed == false` et dont `property` est un `Identifier` : ajouter le nom de la propriété (avec stripping des digits). Les propriétés de member expressions sont **toujours des références libres** (elles ne font pas partie d'un scope).

```javascript
// obj.forEach -> token "forEach"
// arr[0] -> PAS de token supplémentaire (computed == true)
```

#### 4. Valeurs des littéraux

| Type de nœud | Token ajouté | Exemple |
|---|---|---|
| `StringLiteral` | `"S:" + valeur` | `"hello"` -> `S:hello` |
| `NumericLiteral` | `"N:" + valeur` | `42` -> `N:42`, `3.14` -> `N:3.14` |
| `BooleanLiteral` | `"B:" + valeur` | `true` -> `B:true` |
| `NullLiteral` | `"NULL"` | `null` -> `NULL` |
| `RegExpLiteral` | `"R:" + pattern + ":" + flags` | `/abc/gi` -> `R:abc:gi` |
| `BigIntLiteral` | `"I:" + valeur` | `42n` -> `I:42` |
| `TemplateLiteral` | Pour chaque quasis : `"T:" + raw_value` | `` `hello ${x} world` `` -> `T:hello `, `T: world` |

Les prefixes (`S:`, `N:`, etc.) évitent les collisions entre types (ex: la string `"42"` vs le nombre `42`).

#### 5. Normalisation de ObjectExpression

Les propriétés d'un `ObjectExpression` sont triées par nom de clé **avant** d'être visitées. La clé de tri :

- `ObjectProperty` ou `ObjectMethod` dont la `key` est un `Identifier` -> `key.name`
- `key` est un `StringLiteral` -> `key.value`
- `key` est un `NumericLiteral` -> `String(key.value)`
- Sinon (`SpreadElement`, `computed`) -> chaîne vide (l'ordre relatif entre éléments de même clé vide est préservé)

Le tri est **lexicographique** (comparaison de bytes UTF-8).

Raison : certains serveurs sérialisent le JSON dans un ordre différent. `{a: 1, b: 2}` et `{b: 2, a: 1}` doivent produire le même hash.

### Calcul final

Les tokens sont concaténés avec `,` comme séparateur, puis passés à SHA-256 :

```
sha256(tokens.join(","))
```

Le résultat est formaté en `slh1-<hex>`.

---

## Fonctions exposées (API WASM)

### `extractHashes(script: string, minStatements?: number): ExtractResult`

Parse le script JavaScript. Retourne le hash du fichier entier et les hashes de chaque fonction éligible.

Le paramètre `minStatements` contrôle le nombre minimum de statements dans le body d'une fonction pour qu'elle soit hashée. **Valeur par défaut : 3.** La même valeur doit être utilisée lors de la construction de la DB et lors de la vérification, sous peine de manquer des matches.

```typescript
interface FunctionHashInfo {
    /** Library hash du nœud de la fonction (params + body) */
    hash: string;
    /** Nom de la fonction si disponible, null sinon */
    name: string | null;
    /** Position dans le source (lignes 1-indexed, colonnes 0-indexed) */
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
    /** Nombre de statements dans le body */
    stmtCount: number;
}

interface ExtractResult {
    /** Hash du Programme entier */
    fileHash: string;
    /** Hashes de chaque fonction/classe éligible */
    functions: FunctionHashInfo[];
}
```

**Fonctions éligibles :** tout nœud de type :
- `FunctionDeclaration`
- `FunctionExpression`
- `ArrowFunctionExpression`
- `ClassDeclaration`
- `ClassExpression`
- `ObjectMethod`

**Filtrage :** seules les fonctions dont le body (`BlockStatement`) contient **≥ `minStatements` statements** sont incluses. Les arrow functions avec expression body (pas de `BlockStatement`) sont exclues.

Raison du seuil : les fonctions triviales (`function() { return true; }`) sont trop courtes pour être identifiantes et provoqueraient des collisions entre libs différentes.

**Hiérarchie d'extraction :** `extractHashes` retourne **toutes** les fonctions éligibles, y compris les fonctions imbriquées. C'est côté consommateur (le pipeline `sinksight-library-db`) qu'on décide quels hashes mettre dans la DB.

**Hash d'une fonction :** l'algorithme `slh1` est appliqué **au contenu de la fonction** (paramètres + body uniquement). Le type du nœud (`FunctionDeclaration`, `FunctionExpression`, `ArrowFunctionExpression`) et le nom de la fonction ne sont **pas** inclus dans le hash. L'analyse sémantique est recalculée relativement au sous-arbre : les bindings internes à la fonction sont locaux, les bindings externes sont des références libres.

```javascript
// Ces quatre produisent le MÊME hash (même params + même body) :
var foo = function(a, b) { return a + b; };
var bar = function(x, y) { return x + y; };
function foo(a, b) { return a + b; }
function baz(a, b) { return a + b; }
// Les types (FunctionExpression / FunctionDeclaration) et les noms sont ignorés.
```

**Erreur de parsing :** si le script ne parse pas, retourner une erreur (l'appelant devra le gérer). Ne pas retourner un hash de fallback.

### `loadDb(data: Uint8Array): DbHandle`

Charge la base de données binaire dans la mémoire WASM. Retourne un handle opaque.

Le handle est un index interne (u32) vers une structure stockée dans un `Vec<Db>` static côté Rust. L'appelant le passe à `checkScript()`.

L'implémentation doit valider :
- Le magic number du header
- La version de l'algorithme de hash (doit correspondre à `slh1`)
- La valeur de `min_statements` dans le header (voir format DB)
- L'intégrité du header (hash_count, lib_count cohérents avec la taille du blob)

En cas d'erreur -> exception (panic traduit en JS exception par wasm-bindgen).

### `checkScript(dbHandle: DbHandle, script: string): CheckResult`

Parse le script, calcule les hashes, et les compare à la DB chargée. Le `minStatements` est lu depuis la DB elle-même (stocké dans le header).

```typescript
interface LibraryMatch {
    /** Nom de la librairie (ex: "jquery") */
    lib: string;
    /** Version (ex: "3.7.1") */
    version: string;
}

interface FunctionMatch {
    /** Toutes les librairies dont une fonction partage ce hash.
     *  Plusieurs libs sont possibles si elles contiennent la même
     *  fonction (fork, copie de code, polyfill partagé, etc.). */
    libs: LibraryMatch[];
    /** Nom de la fonction original dans la lib (si disponible) */
    functionName: string | null;
    /** Position dans le source (lignes 1-indexed, colonnes 0-indexed) */
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
}

interface CheckResult {
    /** Toutes les libs dont le file hash correspond au script entier.
     *  Tableau vide si aucun match. Plusieurs entrées sont possibles si
     *  le même fichier existe dans plusieurs libs (ex: polyfill identique
     *  republié sous différents noms). */
    wholeFile: LibraryMatch[];
    /** Fonctions individuelles identifiées comme appartenant à une lib.
     *  Seules les fonctions de plus haut niveau matchées sont retournées :
     *  si une fonction parent et une de ses sous-fonctions matchent toutes les deux,
     *  seule la fonction parent apparaît dans cette liste. */
    functions: FunctionMatch[];
}
```

**Algorithme de traversée — DFS avec pruning top-down :**

```
1. Calculer le hash slh1 du Programme entier
2. Lookup dans la DB (file hashes) → collecte de TOUTES les entrées avec ce hash
3. Si match(es) -> retourner { wholeFile: [{ lib, version }, ...], functions: [] }
4. Sinon, traverser l'AST en DFS pré-ordre :
   a. Pour chaque nœud fonction/classe éligible (≥ minStatements statements) :
      i.  Si le nœud est contenu dans une range déjà matchée -> SKIP (ne pas descendre)
      ii. Calculer le hash slh1 du nœud
      iii. Lookup dans la DB (function hashes) → collecte de TOUTES les entrées avec ce hash
      iv. Si match(es) :
            -> Ajouter aux résultats avec libs: [{ lib, version }, ...] et la range
            -> Ajouter aux ranges matchées
            -> NE PAS descendre dans les enfants (pruning)
      v.  Si pas match -> continuer la descente dans les enfants
5. Retourner { wholeFile: [], functions: [...] }
```

**Comportement de hiérarchie :** le pruning top-down garantit que si une fonction parent matche, ses sous-fonctions ne sont jamais examinées ni retournées. Ce comportement est voulu car :
- La range de la fonction parent englobe déjà celle des enfants — côté VS Code, les findings des enfants sont déjà filtrés par la range parent
- Retourner à la fois parent et enfants créerait des doublons dans l'UI (notamment dans les CodeLens)
- C'est plus performant (on évite de hasher les sous-fonctions)

À l'inverse, si une fonction parent ne matche PAS mais que plusieurs de ses sous-fonctions matchent individuellement, toutes les sous-fonctions matchées sont retournées individuellement.

**Erreur de parsing :** si le script ne parse pas, retourner `{ wholeFile: [], functions: [] }` (pas d'erreur — le code peut être du JS invalide intercepté par SinkSight, qui tolère les erreurs de parsing côté Babel).

### `freeDb(dbHandle: DbHandle): void`

Libère la mémoire associée à une DB chargée. Appelé au cleanup de l'extension VS Code.

---

## Format binaire de la base de données

### Structure

```
┌─────────────────────────────────────────────────────────┐
│ HEADER (17 bytes)                                       │
│  [0..3]   magic: "SLH" (3 bytes ASCII)                │
│  [3]      db_version: u8 (actuellement 1)               │
│  [4]      min_statements: u8 (seuil utilisé à la        │
│           construction, vérifié par checkScript)         │
│  [5..9]   lib_count: u32 LE                             │
│  [9..13]  file_hash_count: u32 LE                       │
│  [13..17] func_hash_count: u32 LE                       │
├─────────────────────────────────────────────────────────┤
│ LIB TABLE (variable)                                    │
│  Pour chaque lib (lib_count fois) :                     │
│    lib_id: u16 LE (index, 0-based)                      │
│    name_len: u8                                         │
│    name: [u8; name_len] (UTF-8)                         │
│    version_count: u16 LE                                │
│    Pour chaque version :                                │
│      version_len: u8                                    │
│      version: [u8; version_len] (UTF-8)                 │
├─────────────────────────────────────────────────────────┤
│ FILE HASH TABLE (file_hash_count × 36 bytes)            │
│  Trié par hash (pour binary search)                     │
│  Plusieurs entrées peuvent partager le même hash si     │
│  plusieurs libs produisent le même fichier (les entrées │
│  dupliquées sont contiguës grâce au tri).               │
│  Pour chaque entrée :                                   │
│    hash: [u8; 32] (SHA-256 brut, pas le préfixe slh1) │
│    lib_id: u16 LE                                       │
│    version_index: u16 LE (index dans les versions de    │
│                           cette lib)                    │
├─────────────────────────────────────────────────────────┤
│ FUNCTION HASH TABLE (func_hash_count × 36 bytes)        │
│  Trié par hash (pour binary search)                     │
│  Plusieurs entrées peuvent partager le même hash si     │
│  plusieurs libs contiennent la même fonction (fork,     │
│  polyfill partagé, etc.). Les doublons sont contiguës.  │
│  Pour chaque entrée :                                   │
│    hash: [u8; 32] (SHA-256 brut)                        │
│    lib_id: u16 LE                                       │
│    version_index: u16 LE                                │
├─────────────────────────────────────────────────────────┤
│ BLOOM FILTER (optionnel, pour optimisation)             │
│  bloom_size: u32 LE (en bytes, 0 si absent)             │
│  bloom_hash_count: u8 (nombre de fonctions de hash)     │
│  bloom_data: [u8; bloom_size]                           │
└─────────────────────────────────────────────────────────┘
```

### Lookup

Le lookup d'un hash se fait par **binary search** dans la table triée, puis **scan des voisins** pour collecter toutes les entrées avec le même hash (les tables sont triées, donc les doublons sont contigus) :
- File hash -> binary search dans FILE HASH TABLE, scan gauche+droite
- Function hash -> check optionnel du bloom filter, puis binary search + scan dans FUNCTION HASH TABLE

Ce mécanisme permet à un même hash de retourner plusieurs libs sans aucune modification du format binaire : il suffit que le constructeur de la DB insère plusieurs entrées `(hash, lib_id, version_index)` avec le même hash mais des `lib_id` différents. Le surcoût en lecture est négligeable (scan linéaire sur typiquement 1-2 entrées supplémentaires).

Le bloom filter couvre **uniquement** les function hashes (il y en a beaucoup plus que les file hashes). Si le bloom filter répond "absent", on skip la binary search. Si "peut-être présent", on fait la binary search pour confirmer.

### Notes de sérialisation

- Tous les entiers multi-octets sont en **little-endian**
- Les hashes sont stockés en **bytes bruts** (32 bytes), pas en hex. Le préfixe `slh1-` n'est pas stocké dans la DB — il est implicite (vérifié à `loadDb()` via le `db_version`)
- La DB est conçue pour être chargée quasi-instantanément : les tables de hashes triées peuvent être binary-searched directement depuis le buffer mémoire sans allocation supplémentaire

---

## Compatibilité de parsing

SinkSight utilise Babel avec les options suivantes :

```
sourceType: "unambiguous"
allowAwaitOutsideFunction: true
allowReturnOutsideFunction: true
allowImportExportEverywhere: true
errorRecovery: true
plugins: classProperties, classPrivateProperties, classPrivateMethods,
         dynamicImport, objectRestSpread, optionalChaining,
         nullishCoalescingOperator, topLevelAwait
```

**Ni JSX ni TypeScript ne sont nécessaires.** Tous les scripts analysés par SinkSight sont du JavaScript directement exécutable dans un navigateur.

Le parser oxc côté WASM **doit** produire le même AST (en termes de structure et de tokens collectés) pour le même input.

Points d'attention :

- **sourceType** : le mode `"unambiguous"` de Babel détecte automatiquement `module` vs `script` selon la présence de `import`/`export`. oxc supporte un mode similaire.
- **Error recovery** : Babel continue le parsing malgré des erreurs de syntaxe. oxc a aussi un mode de récupération d'erreurs. Il faut l'activer.

**Test de compatibilité critique :** un corpus de scripts (jQuery, React, Lodash, quelques bundles webpack/rollup) doit produire les **mêmes hashes** qu'une implémentation de référence en JavaScript utilisant l'algorithme `slh1` sur un AST Babel. Ce corpus de test est le garant de la compatibilité. (Voir section Tests.)

En pratique, les différences possibles entre les AST Babel et oxc :
- **Noms de types de nœuds** : doivent correspondre à ESTree. Si oxc utilise des noms différents en interne, un mapping est nécessaire.
- **Structure des enfants** : l'ordre des champs enfants dans un nœud peut différer. La traversée doit utiliser un **ordre de champs défini et fixé** (voir section suivante), pas l'ordre arbitraire de la struct Rust.
- **Scope analysis** : `oxc_semantic` peut classifier les bindings différemment de Babel dans certains edge cases. Les golden tests vérifient la compatibilité end-to-end.

### Ordre de traversée des champs enfants

Pour garantir la compatibilité entre implémentations, les champs enfants de chaque type de nœud sont visités dans un **ordre fixe et spécifié**. Cet ordre correspond à celui défini par `VISITOR_KEYS` de `@babel/types`.

Quelques exemples clés :

```
FunctionDeclaration: [id, params, body]
FunctionExpression: [id, params, body]
ArrowFunctionExpression: [params, body]
ClassDeclaration: [id, superClass, body]
VariableDeclaration: [declarations]
VariableDeclarator: [id, init]
CallExpression: [callee, arguments]
MemberExpression: [object, property]
BinaryExpression: [left, right]
AssignmentExpression: [left, right]
IfStatement: [test, consequent, alternate]
ForStatement: [init, test, update, body]
ObjectExpression: [properties]  ← triées par clé avant visite
ReturnStatement: [argument]
BlockStatement: [body]
Program: [body]
```

La liste complète doit être extraite de `@babel/types` VISITOR_KEYS et hardcodée dans le code Rust (ou générée à partir de cette source). **Toute divergence dans l'ordre de visite des champs produit des hashes différents et casse la compatibilité.**

---

## Pile technique

- **Langage** : Rust
- **Parser** : `oxc_parser` (crate oxc)
- **Analyse sémantique** : `oxc_semantic` (crate oxc) — pour la classification des bindings locaux/libres
- **SHA-256** : `sha2` crate (ou `ring` — au choix, `sha2` est plus léger pour du WASM)
- **WASM binding** : `wasm-bindgen` + `serde-wasm-bindgen` (crate `wasm`)
- **NAPI binding** : `napi-rs` v3 (crate `napi`) — addon natif Node.js
- **Build WASM** : `wasm-pack build --target nodejs` (pour l'extension VS Code)
- **Build NAPI** : `napi build --platform --release` (pour `sinksight-library-db`)

---

## Tests

### Tests unitaires Rust

- Vérifier que des scripts identiques reformatés produisent le même hash
- Vérifier que des scripts avec commentaires ajoutés/supprimés produisent le même hash
- Vérifier que des scripts avec changement CRLF -> LF produisent le même hash
- Vérifier que le renommage de variables locales ne change PAS le hash
- Vérifier que le renommage de paramètres de fonction ne change PAS le hash
- Vérifier que le renommage du nom d'une fonction (son `id`) ne change PAS le hash de cette fonction
- Vérifier que le changement de type d'une fonction (`FunctionDeclaration` vs `FunctionExpression` vs `ArrowFunctionExpression`) ne change PAS le hash de cette fonction
- Vérifier que le renommage d'une référence libre CHANGE le hash
- Vérifier que le changement d'une propriété de member expression CHANGE le hash
- Vérifier que l'ajout d'une ligne de code change le hash
- Vérifier que le changement d'une valeur de string literal change le hash
- Vérifier que la réorganisation des clés d'un objet ne change PAS le hash
- Vérifier le seuil configurable de statements (tester avec différentes valeurs)
- Vérifier le pruning top-down dans `checkScript`
- Vérifier que les fonctions enfants ne sont pas retournées quand le parent matche
- Vérifier que les fonctions enfants SONT retournées quand le parent ne matche pas
- Vérifier le format du hash (`slh1-` + 64 hex chars)
- Vérifier `loadDb` avec une DB invalide (mauvais magic, mauvaise version)
- Vérifier `loadDb` + `checkScript` avec une DB valide
- Vérifier qu'un hash partagé par deux libs retourne bien les deux libs
- Vérifier `checkScript` avec une DB contenant des hashes dupliqués (multi-lib) → `libs` contient toutes les libs

### Golden tests (corpus de compatibilité)

Un répertoire `tests/golden/` contient des fichiers JavaScript de librairies connues. Les fichiers de scripts sont **gitignorés** et doivent être téléchargés explicitement via un script dédié avant d'exécuter les golden tests.

Structure :
```
tests/golden/
├── manifest.json              # Liste des fichiers à télécharger avec URL + SHA-256
├── scripts/                   # Gitignored — à télécharger via scripts/download-fixtures.ts
│   ├── jquery-3.7.1.js
│   ├── jquery-3.7.1.min.js
│   ├── lodash-4.17.21.js
│   ├── react-18.2.0.umd.js
│   └── ...
└── expected/                  # Commité — résultats attendus
    ├── jquery-3.7.1.json      # { fileHash: "slh1-...", functions: [...] }
    ├── lodash-4.17.21.json
    └── ...
```

**Téléchargement des fixtures :** le script `scripts/download-fixtures.ts` (TypeScript, Node.js) lit `manifest.json`, vérifie si chaque fichier est déjà présent dans `tests/golden/scripts/`, télécharge les fichiers manquants depuis le CDN indiqué (`fetch` natif Node 18+), et vérifie le SHA-256 de chaque fichier téléchargé contre le manifest (`crypto.createHash` stdlib). Il s'exécute avec :

```sh
npx tsx scripts/download-fixtures.ts
```

En CI, cette commande est une étape dédiée, exécutée avant `cargo test`, avec mise en cache du répertoire `tests/golden/scripts/` entre les runs.

**Manifest (`manifest.json`) :**
```json
[
  {
    "name": "jquery-3.7.1.js",
    "url": "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.js",
    "sha256": "abc123..."
  },
  {
    "name": "jquery-3.7.1.min.js",
    "url": "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
    "sha256": "def456..."
  }
]
```

Le répertoire `tests/golden/scripts/` est dans le `.gitignore`. Les golden tests vérifient en début d'exécution que les fixtures sont présentes ; **si un fichier est manquant, le test est ignoré (`#[ignore]`)** avec un message indiquant de lancer `npx tsx scripts/download-fixtures.ts`. `cargo test` reste ainsi entièrement offline et reproductible.

Chaque fichier `expected/*.json` contient les résultats attendus de `extractHashes()` :
- Le `fileHash` exact
- La liste des `functions` avec leurs hashes, noms, et positions

**Ces fichiers sont générés une fois par une implémentation de référence.** Cette implémentation de référence peut être :
- En TypeScript utilisant Babel + l'algorithme `slh1` écrit en TS (script dans `scripts/generate-golden.ts`)
- Ou directement par la première version stable de l'implémentation Rust, validée manuellement

### Tests d'intégration

- Construire une mini-DB (2-3 libs, quelques versions)
- `loadDb()` -> `checkScript()` avec :
  - Un fichier jQuery non modifié -> `wholeFile` doit matcher (tableau non vide)
  - Un fichier jQuery reformaté (Prettier) -> `wholeFile` doit matcher
  - Un fichier jQuery avec variables locales renommées -> `wholeFile` doit matcher
  - Un bundle webpack contenant jQuery + code métier -> `functions` doit identifier les fonctions jQuery, pas le code métier
  - Un fichier de code métier pur -> rien ne doit matcher
  - Un fichier jQuery minifié (avec mangle structural) -> rien ne doit matcher (comportement safe)
  - Fonction parent et enfant dans la DB -> seule la fonction parent est retournée
  - Seulement la fonction enfant dans la DB (pas le parent) -> la fonction enfant est retournée

---

## Package npm — structure de publication

```
@sinksight/library-hash/
├── package.json
├── sinksight_library_hash_bg.wasm
├── sinksight_library_hash.js      # glue JS (généré par wasm-pack)
├── sinksight_library_hash.d.ts    # types TypeScript
└── README.md
```

Le `package.json` :
```json
{
  "name": "@sinksight/library-hash",
  "version": "1.0.0",
  "description": "WASM library for computing and verifying SinkSight Library Hashes (SLH)",
  "main": "sinksight_library_hash.js",
  "types": "sinksight_library_hash.d.ts",
  "files": [
    "sinksight_library_hash_bg.wasm",
    "sinksight_library_hash.js",
    "sinksight_library_hash.d.ts"
  ],
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/crazycat256/sinksight"
  }
}
```

---

## Consommation côté VS Code (pour référence)

Le résultat de `checkScript()` est utilisé dans `ScriptManager.handleScript()` pour :

1. **Si `wholeFile` n'est pas vide** : le script est une lib connue. On court-circuite tout le pipeline Babel (`analyzeAndPrettify()` n'est pas appelé). Le fichier est quand même écrit sur disque mais marqué comme lib dans SQLite. Aucun diagnostic VS Code n'est émis. Un `FileDecorationProvider` grise le fichier dans l'explorateur (badge "L", couleur `disabledForeground`). Un `CodeLensProvider` affiche en haut du fichier la ou les libs identifiées (ex: `"📦 jQuery 3.7.1 — excluded from analysis"` ou `"📦 jQuery 3.7.1, core-js 3.0.0 — excluded from analysis"` si plusieurs libs partagent le même fichier).

2. **Si `functions` n'est pas vide** : le script est un bundle partiel. On exécute `analyzeAndPrettify()` normalement, puis on filtre les findings dont la position (`startLine..endLine`) tombe dans une range matchée. Les ranges matchées sont utilisées par :
   - Un `TextEditorDecorationType` avec `opacity: 0.5` pour semi-griser les portions de lib dans l'éditeur
   - Un `CodeLensProvider` qui affiche au-dessus de chaque range matchée le nom et la version de la ou des libs identifiées (ex: `"📦 jQuery 3.7.1 — excluded from analysis"` ou `"📦 jQuery 3.7.1, core-js 3.0.0 — excluded from analysis"` si la fonction existe dans plusieurs libs). Chaque range a son propre CodeLens.

3. **Si rien ne matche** : analyse classique, aucun filtrage.

---

## Résumé des invariants critiques

1. **Deux inputs identiques modulo whitespace/commentaires/noms-de-variables-locales DOIVENT produire le même hash.** C'est la raison d'être du hash AST avec normalisation des bindings locaux.

2. **Deux inputs qui diffèrent par une valeur de littéral ou une référence libre DOIVENT produire des hashes différents.** Sinon on risque des faux positifs (identifier comme lib du code qui ne l'est pas).

3. **L'algorithme de hash est versioned.** Un changement de l'algo nécessite un bump de version (`slh1` -> `slh2`), une régénération complète de la DB, et une mise à jour du module WASM.

4. **Le module WASM ne produit jamais de faux négatif dangereux.** Si un script n'est pas reconnu, il est analysé normalement. Le pire cas est de ne pas reconnaître une lib (faux positifs non filtrés), jamais de skipper l'analyse de code métier (faux négatifs de détection XSS).

5. **Le format de DB est versionné.** `db_version` dans le header permet de rejeter une DB incompatible.

6. **L'ordre de visite des champs enfants est fixé et documenté.** Toute divergence casse la compatibilité. Les golden tests sont le filet de sécurité.

7. **Le seuil de statements minimum est configurable et stocké dans la DB.** Il doit être identique entre la construction de la DB et la vérification.

8. **Seules les fonctions de plus haut niveau matchées sont retournées.** Si une fonction parent matche, ses enfants ne sont ni hashés ni retournés (pruning top-down).
