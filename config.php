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
