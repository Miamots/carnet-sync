# Carnet d'observation nature

Carnet d'observation ergo pour la classe nature (fiches 0-4 ans et 4-5 ans).
Tout reste sur l'appareil : rien n'est envoyé en ligne.

## Mettre en ligne sur GitHub Pages

1. Créez un dépôt (ex. `carnet-nature`) ou ouvrez un dépôt existant.
2. Téléversez **tout le contenu** de ce dossier à la racine du dépôt : `index.html`, `manifest.webmanifest`, `sw.js`, `README.md` et le dossier `img/`.
3. Dans le dépôt : **Settings → Pages → Build and deployment → Source : Deploy from a branch**, branche `main`, dossier `/ (root)`, puis **Save**.
4. Après une minute ou deux, le carnet est en ligne à `https://VOTRE-NOM.github.io/carnet-nature/`.

Le code du dépôt peut être public : il ne contient aucune donnée d'enfant.

## L'installer sur le téléphone (fonctionne sans réseau)

- **Android (Chrome)** : ouvrez le lien, menu ⋮ → **Ajouter à l'écran d'accueil** ou **Installer l'application**.
- **iPhone (Safari)** : ouvrez le lien, bouton Partager → **Sur l'écran d'accueil**.

Ouvrez-le une fois avec du réseau. Ensuite, il fonctionne en forêt sans connexion.

## Les données

- Les observations et les photos sont gardées **sur l'appareil où vous les entrez**.
- Faites une **sauvegarde** régulièrement (page d'accueil → Sauvegarde et partage). Gardez le fichier en lieu sûr.
- Effacer les données du navigateur ou désinstaller l'application efface le carnet : la sauvegarde est votre filet.

## Travailler à deux

1. **Au départ**, une seule personne crée le groupe et les enfants, fait une sauvegarde, et l'autre fait **Restaurer (remplacer tout)** une seule fois. Vous partez ainsi avec les mêmes enfants.
2. Chacune remplit son carnet.
3. De temps en temps, une personne envoie sa sauvegarde (avec photos) et l'autre fait **Fusionner une sauvegarde**. Tout est combiné sans doublons : cases, « pas encore », notes, photos, objectifs, présences.
4. Si une même information a deux valeurs différentes (un texte de synthèse, un objectif du même jour, une langue…), l'écran **À trancher** vous laisse choisir. Ce qui a été supprimé d'un côté reste supprimé.
5. Indiquez votre prénom dans **Paramètres → Moi** : vos notes sont signées et les fichiers de sauvegarde portent votre nom.

## L'IA (notes dictées, portraits, notes du jour)

Le carnet ne contient pas d'IA. Il prépare des demandes à copier dans votre IA (Claude, Gemini ou ChatGPT, au choix dans les Paramètres) :

- **Paramètres → Mon IA et mes notes → Copier les instructions** : à coller une fois dans votre projet IA. Votre IA ajoute ensuite à chaque note un « bloc carnet » que le carnet lit directement.
- **Note complète du groupe** : collez la note de votre IA (avec son bloc) et le carnet classe tout ; vous relisez avant d'enregistrer.
- **Notes du jour** : mettre au propre les notes prises sur le moment, ou rédiger la note complète de la journée.
- **Brouillon avec votre IA** dans les portraits par occupation.

Recopiez les instructions quand vous ajoutez un enfant, un objectif ou des repères.

## Mettre à jour le carnet

Remplacez les fichiers dans le dépôt, puis changez la ligne `const VERSION="carnet-v2";` dans `sw.js`
(ex. `carnet-v3`). Les appareils prendront la nouvelle version à la prochaine ouverture avec réseau.
Les données sur les appareils ne sont pas touchées.
