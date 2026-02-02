<?php
// backend/config.php

define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'sonef_transport');
define('DB_USER', 'root');
define('DB_PASS', '');

// Durée du token (jours)
define('TOKEN_TTL_DAYS', 30);

// Pour QR payload (simple) et signature éventuelle
define('APP_SECRET', 'CHANGE_ME__SONEF_SECRET_2025');

// Logs debug connexion (mettre à false en prod)
define('LOG_CONNEXION', true);

// API externe SONEF (synchro villes, etc.)
define('EXTERNAL_API_BASE', 'http://162.43.192.47:9000');
// Token Bearer pour s'authentifier auprès de l'API externe (obligatoire si l'API renvoie 401)
define('EXTERNAL_API_TOKEN', 'gfhvilk,l;56d4dhkbjsdjhbnsd5s54skhshvjsghjs543qsjkbxghbd!:;s:uihsdutgyhs');
// Clé optionnelle pour sécuriser l'appel à synchro_villes (laisser vide = pas de vérification)
define('SYNC_SECRET', '');
