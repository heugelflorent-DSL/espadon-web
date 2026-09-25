# Espadon Web

Analyse vidéo de courses de natation : pointage au clavier image par image, calculs (vitesse, fréquence, amplitude, coulées, virages) et rapport PDF.

- `index.html` : l'application (fonctionne aussi seule, en mode navigateur).
- `netlify/functions/api.mjs` : comptes (inscription + validation par l'admin), historique des analyses par entraîneur, administration.
- Stockage : Netlify Blobs (`espadon` en production, `espadon-test` pour les branches de test). Aucune vidéo n'est stockée.
- Variables Netlify requises : `ADMIN_EMAIL` (super admin), `SESSION_SECRET` (48+ caractères aléatoires).

Publication : branche `test` → prévisualisation Netlify ; `main` → production.
