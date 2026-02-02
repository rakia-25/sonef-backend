<?php
// backend/api.php

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

require_once __DIR__ . "/Rest.inc.php";
require_once __DIR__ . "/config.php";
require_once __DIR__ . "/utils.php";

class API extends REST
{
    private mysqli $db;

    public function __construct()
    {
        parent::__construct();
        $this->dbConnect();
    }

    private function dbConnect(): void
    {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($this->db->connect_error) {
            $this->response(json_out(['ok' => false, 'message' => 'DB connection error']), 500);
        }
        $this->db->set_charset("utf8mb4");
    }

    // Routing "style api.php fourni" via ?rquest=...
    public function processApi(): void
    {
        $func = strtolower(trim(str_replace("/", "", $_REQUEST['rquest'] ?? '')));
        if ($func && method_exists($this, $func)) {
            $this->$func();
        } else {
            $this->response(json_out(['ok' => false, 'message' => 'Endpoint introuvable']), 404);
        }
    }

    private function trajets_heures_depart(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $id_dep = (int)($this->_request['id_ville_depart'] ?? 0);
        $id_arr = (int)($this->_request['id_ville_arrivee'] ?? 0);
        $date   = trim((string)($this->_request['date_depart'] ?? '')); // optionnel

        if (!$id_dep || !$id_arr) {
            $this->response(json_out(['ok' => false, 'message' => 'id_ville_depart et id_ville_arrivee requis']), 400);
        }

        $sql = "SELECT DISTINCT t.heure_depart
            FROM trajets t
            JOIN lignes l ON l.id_ligne = t.id_ligne
            WHERE l.actif=1
              AND l.id_ville_depart=? AND l.id_ville_arrivee=?
              AND t.statut <> 'annule'";

        if ($date !== '') {
            $sql .= " AND t.date_depart=?";
        }

        $sql .= " ORDER BY t.heure_depart ASC";

        $stmt = $this->db->prepare($sql);
        if (!$stmt) {
            $this->response(json_out(['ok' => false, 'message' => 'Prepare failed', 'error' => $this->db->error]), 500);
        }

        if ($date !== '') {
            $stmt->bind_param("iis", $id_dep, $id_arr, $date);
        } else {
            $stmt->bind_param("ii", $id_dep, $id_arr);
        }

        if (!$stmt->execute()) {
            $err = $stmt->error ?: 'Execute failed';
            $stmt->close();
            $this->response(json_out(['ok' => false, 'message' => 'Erreur SQL', 'error' => $err]), 500);
        }

        $res = $stmt->get_result();
        $heures = [];
        while ($r = $res->fetch_assoc()) {
            if (!empty($r['heure_depart'])) $heures[] = $r['heure_depart']; // ex: 08:00:00
        }
        $stmt->close();

        $this->response(json_out(['ok' => true, 'heures' => $heures]), 200);
    }



    private function normalizeE164(string $indicatif, string $numero): string
    {
        $indicatif = trim($indicatif);
        $numero = preg_replace('/\D+/', '', $numero);

        if ($indicatif === '') $indicatif = '+227';
        if ($indicatif[0] !== '+') $indicatif = '+' . preg_replace('/\D+/', '', $indicatif);

        // Si l'utilisateur met déjà +2279960..., on le garde
        if (strpos($numero, '00') === 0) $numero = substr($numero, 2); // 00227 -> 227
        if (strpos($numero, '+') === 0) return $numero;

        return $indicatif . $numero;
    }

    // -------------------------
    // Auth helpers
    // -------------------------
    private function requireAuth(): array
    {
        $token = get_bearer_token();
        if (!$token) {
            $this->response(json_out(['ok' => false, 'message' => 'Token manquant']), 401);
        }

        $sql = "SELECT u.* FROM jetons_acces t
                JOIN utilisateurs u ON u.id_utilisateur = t.id_utilisateur
                WHERE t.jeton = ? AND t.date_expiration > NOW() AND u.statut = 1
                LIMIT 1";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $res = $stmt->get_result();
        $user = $res->fetch_assoc();
        $stmt->close();

        if (!$user) {
            $this->response(json_out(['ok' => false, 'message' => 'Token invalide/expiré']), 401);
        }
        return $user;
    }

    private function safeStr(string $key, int $max = 255): string
    {
        $v = trim((string)($this->_request[$key] ?? ''));
        if (mb_strlen($v) > $max) $v = mb_substr($v, 0, $max);
        return $v;
    }

    private function safeInt(string $key): int
    {
        return (int)($this->_request[$key] ?? 0);
    }

    // -------------------------
    // Public endpoints
    // -------------------------
    private function getversion(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);
        $this->response(json_out(['ok' => true, 'version' => '1.0.0']), 200);
    }

    private function tarifs_colis_liste(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $res = $this->db->query("SELECT * FROM tarifs_colis WHERE actif=1 ORDER BY poids_min ASC");
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;

        $this->response(json_out(['ok' => true, 'tarifs_colis' => $rows]), 200);
    }

    private function tarifs_billets_liste(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        // Simple: on renvoie les lignes + prix min (ou trajets à venir)
        $sql = "SELECT l.id_ligne, l.nom_ligne,
                   vd.nom_ville AS ville_depart, va.nom_ville AS ville_arrivee,
                   MIN(t.prix) AS prix_min, MAX(t.prix) AS prix_max, 'XOF' AS devise
            FROM lignes l
            JOIN villes vd ON vd.id_ville=l.id_ville_depart
            JOIN villes va ON va.id_ville=l.id_ville_arrivee
            LEFT JOIN trajets t ON t.id_ligne=l.id_ligne AND t.statut<>'annule'
            WHERE l.actif=1
            GROUP BY l.id_ligne, l.nom_ligne, vd.nom_ville, va.nom_ville
            ORDER BY vd.nom_ville, va.nom_ville";
        $res = $this->db->query($sql);
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;

        $this->response(json_out(['ok' => true, 'tarifs_billets' => $rows]), 200);
    }

    private function profil_password_update(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $old = (string)($this->_request['ancien_mot_de_passe'] ?? '');
        $new = (string)($this->_request['nouveau_mot_de_passe'] ?? '');

        if (!$old || strlen($new) < 6) {
            $this->response(json_out(['ok' => false, 'message' => 'Paramètres invalides']), 400);
        }

        // récupérer hash actuel
        $stmt = $this->db->prepare("SELECT mot_de_passe_hash FROM utilisateurs WHERE id_utilisateur=? LIMIT 1");
        $stmt->bind_param("i", $u['id_utilisateur']);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$row || !password_verify($old, $row['mot_de_passe_hash'])) {
            $this->response(json_out(['ok' => false, 'message' => 'Ancien mot de passe incorrect']), 401);
        }

        // Optionnel: si le hash est ancien, on peut rehash (pas obligatoire)
        $hash = password_hash($new, PASSWORD_BCRYPT);

        $this->db->begin_transaction();
        try {
            $stmt = $this->db->prepare("UPDATE utilisateurs SET mot_de_passe_hash=? WHERE id_utilisateur=?");
            $stmt->bind_param("si", $hash, $u['id_utilisateur']);
            $stmt->execute();
            $stmt->close();

            // ✅ recommandé: invalider les autres jetons (sécurité)
            $stmt = $this->db->prepare("DELETE FROM jetons_acces WHERE id_utilisateur=?");
            $stmt->bind_param("i", $u['id_utilisateur']);
            $stmt->execute();
            $stmt->close();

            // (Optionnel) recréer un token et le renvoyer
            $token = random_token64();
            $exp = mysql_add_days(TOKEN_TTL_DAYS);
            $ip = $_SERVER['REMOTE_ADDR'] ?? null;
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

            $stmt = $this->db->prepare("INSERT INTO jetons_acces(id_utilisateur, jeton, date_expiration, ip, user_agent)
                                    VALUES(?,?,?,?,?)");
            $stmt->bind_param("issss", $u['id_utilisateur'], $token, $exp, $ip, $ua);
            $stmt->execute();
            $stmt->close();

            $this->db->commit();

            $this->response(json_out([
                'ok' => true,
                'token' => $token,
                'date_expiration' => $exp
            ]), 200);
        } catch (Throwable $e) {
            $this->db->rollback();
            $this->response(json_out(['ok' => false, 'message' => 'Erreur changement mot de passe']), 500);
        }
    }

    private function contenu_page(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);
        $slug = $this->safeStr('slug', 60);
        if (!$slug) $this->response(json_out(['ok' => false, 'message' => 'slug requis']), 400);

        $stmt = $this->db->prepare("SELECT slug,titre,contenu_html,date_maj FROM contenus_pages WHERE actif=1 AND slug=? LIMIT 1");
        $stmt->bind_param("s", $slug);
        $stmt->execute();
        $p = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$p) $this->response(json_out(['ok' => false, 'message' => 'introuvable']), 404);
        $this->response(json_out(['ok' => true, 'page' => $p]), 200);
    }
    private function otp_envoyer(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        $indicatif = $this->safeStr('indicatif_pays', 6) ?: '+227';
        $numero = $this->safeStr('telephone_national', 30);
        $canal = strtolower($this->safeStr('canal', 20) ?: 'whatsapp'); // whatsapp|sms
        $usage = $this->safeStr('usage_code', 40) ?: 'inscription';
        if ($usage === 'mot_de_passe_oublie') $usage = 'reset_mdp';

        if (!$numero) $this->response(json_out(['ok' => false, 'message' => 'Téléphone requis']), 400);

        $telE164 = $this->normalizeE164($indicatif, $numero);

        // throttle simple: pas plus d'un OTP/minute
        $stmt = $this->db->prepare("SELECT date_creation FROM otp_codes WHERE telephone_e164=? AND usage_code=? ORDER BY id_otp DESC LIMIT 1");
        $stmt->bind_param("ss", $telE164, $usage);
        $stmt->execute();
        $last = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if ($last) {
            $lastTs = strtotime($last['date_creation']);
            if (time() - $lastTs < 60) {
                $this->response(json_out(['ok' => false, 'message' => 'Attends 1 minute avant de renvoyer un code.']), 429);
            }
        }

        $code = strval(random_int(100000, 999999));
        $exp = date('Y-m-d H:i:s', time() + 10 * 60); // 10 min

        $stmt = $this->db->prepare("INSERT INTO otp_codes(telephone, indicatif_pays, telephone_e164, code, usage_code, canal, date_expiration)
                                VALUES(?,?,?,?,?,?,?)");
        if (!$stmt) {
            $this->response(json_out(['ok' => false, 'message' => 'Erreur préparation requête OTP', 'error' => $this->db->error]), 500);
        }
        $telRaw = $indicatif . $numero;
        $stmt->bind_param("sssssss", $telRaw, $indicatif, $telE164, $code, $usage, $canal, $exp);
        if (!$stmt->execute()) {
            $err = $stmt->error ?: $this->db->error;
            $stmt->close();
            $this->response(json_out(['ok' => false, 'message' => 'Impossible d\'enregistrer le code OTP', 'error' => $err]), 500);
        }
        $stmt->close();

        // TODO prod: envoyer via API WhatsApp/SMS
        // DEV: on renvoie le code pour test
        $this->response(json_out([
            'ok' => true,
            'telephone_e164' => $telE164,
            'expire_le' => $exp,
            'dev_code' => $code
        ]), 200);
    }
    private function mdp_reset_confirmer(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        $telE164 = $this->safeStr('telephone_e164', 40);
        $code = $this->safeStr('code_otp', 10);
        $newPass = (string)($this->_request['nouveau_mot_de_passe'] ?? '');

        if (!$telE164 || !$code || strlen($newPass) < 6) {
            $this->response(json_out(['ok' => false, 'message' => 'Paramètres invalides']), 400);
        }

        // Vérifier OTP reset_mdp
        $stmt = $this->db->prepare("SELECT id_otp, utilise, date_expiration
                                FROM otp_codes
WHERE telephone_e164=? AND (usage_code='reset_mdp' OR usage_code='mot_de_passe_oublie') AND code=?
                                ORDER BY id_otp DESC LIMIT 1");
        $stmt->bind_param("ss", $telE164, $code);
        $stmt->execute();
        $o = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$o) $this->response(json_out(['ok' => false, 'message' => 'OTP invalide']), 401);
        if ((int)$o['utilise'] === 1) $this->response(json_out(['ok' => false, 'message' => 'OTP déjà utilisé']), 409);
        if (strtotime($o['date_expiration']) < time()) $this->response(json_out(['ok' => false, 'message' => 'OTP expiré']), 410);

        // User existe ?
        $stmt = $this->db->prepare("SELECT id_utilisateur FROM utilisateurs WHERE telephone_e164=? AND statut=1 LIMIT 1");
        $stmt->bind_param("s", $telE164);
        $stmt->execute();
        $u = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$u) $this->response(json_out(['ok' => false, 'message' => 'Compte introuvable']), 404);

        $hash = password_hash($newPass, PASSWORD_BCRYPT);

        $this->db->begin_transaction();
        try {
            $stmt = $this->db->prepare("UPDATE utilisateurs SET mot_de_passe_hash=? WHERE id_utilisateur=?");
            $stmt->bind_param("si", $hash, $u['id_utilisateur']);
            $stmt->execute();
            $stmt->close();

            $this->db->query("UPDATE otp_codes SET utilise=1 WHERE id_otp=" . (int)$o['id_otp']);

            $this->db->commit();
            $this->response(json_out(['ok' => true]), 200);
        } catch (Throwable $e) {
            $this->db->rollback();
            $this->response(json_out(['ok' => false, 'message' => 'Erreur reset mot de passe']), 500);
        }
    }

    private function mdp_changer(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $old = (string)($this->_request['ancien_mot_de_passe'] ?? '');
        $new = (string)($this->_request['nouveau_mot_de_passe'] ?? '');

        if (!$old || strlen($new) < 6) {
            $this->response(json_out(['ok' => false, 'message' => 'Paramètres invalides']), 400);
        }

        // récupérer hash actuel
        $stmt = $this->db->prepare("SELECT mot_de_passe_hash FROM utilisateurs WHERE id_utilisateur=? LIMIT 1");
        $stmt->bind_param("i", $u['id_utilisateur']);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$row || !password_verify($old, $row['mot_de_passe_hash'])) {
            $this->response(json_out(['ok' => false, 'message' => 'Ancien mot de passe incorrect']), 401);
        }

        $hash = password_hash($new, PASSWORD_BCRYPT);
        $stmt = $this->db->prepare("UPDATE utilisateurs SET mot_de_passe_hash=? WHERE id_utilisateur=?");
        $stmt->bind_param("si", $hash, $u['id_utilisateur']);
        $stmt->execute();
        $stmt->close();

        $this->response(json_out(['ok' => true]), 200);
    }


    //format image 1200 × 500
    private function bannieres_actives(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $now = date('Y-m-d H:i:s');

        $sql = "SELECT id, titre, image_url, lien_type, lien_valeur, date_debut, date_fin
            FROM banniere_promotions
            WHERE statut = 1
              AND date_debut <= ?
              AND date_fin >= ?
            ORDER BY date_debut DESC, id DESC
            LIMIT 10";

        $stmt = $this->db->prepare($sql);
        if (!$stmt) {
            $this->response(json_out(['ok' => false, 'message' => 'Prepare failed']), 500);
        }

        $stmt->bind_param("ss", $now, $now);
        $stmt->execute();
        $res = $stmt->get_result();

        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;

        $stmt->close();

        $this->response(json_out([
            'ok' => true,
            'items' => $rows,
            'server_time' => $now
        ]), 200);
    }

    private function otp_verifier(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        $telE164 = $this->safeStr('telephone_e164', 40);
        $code = $this->safeStr('code', 10);
        $usage = $this->safeStr('usage_code', 40) ?: 'inscription';

        if (!$telE164 || !$code) $this->response(json_out(['ok' => false, 'message' => 'Paramètres requis']), 400);

        $stmt = $this->db->prepare("SELECT id_otp, utilise, date_expiration
                                FROM otp_codes
                                WHERE telephone_e164=? AND usage_code=? AND code=?
                                ORDER BY id_otp DESC LIMIT 1");
        $stmt->bind_param("sss", $telE164, $usage, $code);
        $stmt->execute();
        $o = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$o) $this->response(json_out(['ok' => false, 'message' => 'Code invalide']), 401);
        if ((int)$o['utilise'] === 1) $this->response(json_out(['ok' => false, 'message' => 'Code déjà utilisé']), 409);
        if (strtotime($o['date_expiration']) < time()) $this->response(json_out(['ok' => false, 'message' => 'Code expiré']), 410);

        // Marquer utilisé
        $id = (int)$o['id_otp'];
        $this->db->query("UPDATE otp_codes SET utilise=1 WHERE id_otp=" . $id);

        $this->response(json_out(['ok' => true]), 200);
    }

    private function inscription_confirmer(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        $nom = $this->safeStr('nom', 80);
        $prenom = $this->safeStr('prenom', 80);
        $indicatif = $this->safeStr('indicatif_pays', 6) ?: '+227';
        $telNational = $this->safeStr('telephone_national', 30);
        $mdp = (string)($this->_request['mot_de_passe'] ?? '');
        $code = $this->safeStr('code_otp', 10);

        if (!$nom || !$prenom || !$telNational || strlen($mdp) < 6 || !$code) {
            $this->response(json_out(['ok' => false, 'message' => 'Champs invalides']), 400);
        }

        $telE164 = $this->normalizeE164($indicatif, $telNational);

        // Vérifier OTP (utilise=0 etc.)
        $stmt = $this->db->prepare("SELECT id_otp, utilise, date_expiration
                                FROM otp_codes
                                WHERE telephone_e164=? AND usage_code='inscription' AND code=?
                                ORDER BY id_otp DESC LIMIT 1");
        $stmt->bind_param("ss", $telE164, $code);
        $stmt->execute();
        $o = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$o) $this->response(json_out(['ok' => false, 'message' => 'OTP invalide']), 401);
        if ((int)$o['utilise'] === 1) $this->response(json_out(['ok' => false, 'message' => 'OTP déjà utilisé']), 409);
        if (strtotime($o['date_expiration']) < time()) $this->response(json_out(['ok' => false, 'message' => 'OTP expiré']), 410);

        // Vérifier si user existe
        $stmt = $this->db->prepare("SELECT id_utilisateur FROM utilisateurs WHERE telephone_e164=? LIMIT 1");
        $stmt->bind_param("s", $telE164);
        $stmt->execute();
        $exists = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if ($exists) $this->response(json_out(['ok' => false, 'message' => 'Téléphone déjà utilisé']), 409);

        $hash = password_hash($mdp, PASSWORD_BCRYPT);
        $id_role = 1; // client

        $this->db->begin_transaction();
        try {
            // create user
            $stmt = $this->db->prepare("INSERT INTO utilisateurs(id_role, nom, prenom, indicatif_pays, telephone_national, telephone_e164, telephone, mot_de_passe_hash, otp_verifie, date_verification)
                                    VALUES(?,?,?,?,?,?,?, ?, 1, NOW())");
            // colonne "telephone" gardée pour compat: on stocke aussi telE164
            $telCompat = $telE164;
            $stmt->bind_param("isssssss", $id_role, $nom, $prenom, $indicatif, $telNational, $telE164, $telCompat, $hash);
            $stmt->execute();
            $userId = (int)$stmt->insert_id;
            $stmt->close();

            // mark OTP used
            $idOtp = (int)$o['id_otp'];
            $this->db->query("UPDATE otp_codes SET utilise=1 WHERE id_otp=" . $idOtp);

            // issue token
            $token = random_token64();
            $exp = mysql_add_days(TOKEN_TTL_DAYS);
            $ip = $_SERVER['REMOTE_ADDR'] ?? null;
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

            $stmt = $this->db->prepare("INSERT INTO jetons_acces(id_utilisateur, jeton, date_expiration, ip, user_agent)
                                    VALUES(?,?,?,?,?)");
            $stmt->bind_param("issss", $userId, $token, $exp, $ip, $ua);
            $stmt->execute();
            $stmt->close();

            $this->db->commit();

            $this->response(json_out([
                'ok' => true,
                'token' => $token,
                'date_expiration' => $exp,
                'utilisateur' => [
                    'id_utilisateur' => $userId,
                    'nom' => $nom,
                    'prenom' => $prenom,
                    'telephone_e164' => $telE164
                ]
            ]), 200);
        } catch (Throwable $e) {
            $this->db->rollback();
            $this->response(json_out(['ok' => false, 'message' => 'Erreur inscription']), 500);
        }
    }

    private function inscription(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        $nom = $this->safeStr('nom', 80);
        $prenom = $this->safeStr('prenom', 80);
        $telephone = $this->safeStr('telephone', 30);
        $email = $this->safeStr('email', 120);
        $mdp = (string)($this->_request['mot_de_passe'] ?? '');

        if (!$nom || !$prenom || !$telephone || strlen($mdp) < 6) {
            $this->response(json_out(['ok' => false, 'message' => 'Champs invalides']), 400);
        }

        // rôle client
        $id_role = 1;

        // vérif unicité tel/email
        $sql = "SELECT id_utilisateur FROM utilisateurs WHERE telephone=? OR (email IS NOT NULL AND email=? ) LIMIT 1";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("ss", $telephone, $email);
        $stmt->execute();
        $exists = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if ($exists) {
            $this->response(json_out(['ok' => false, 'message' => 'Téléphone/email déjà utilisé']), 409);
        }

        $hash = password_hash($mdp, PASSWORD_BCRYPT);

        $sql = "INSERT INTO utilisateurs(id_role, nom, prenom, telephone, email, mot_de_passe_hash)
                VALUES(?,?,?,?,?,?)";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("isssss", $id_role, $nom, $prenom, $telephone, $email, $hash);
        $ok = $stmt->execute();
        $newId = $stmt->insert_id;
        $stmt->close();

        if (!$ok) {
            $this->response(json_out(['ok' => false, 'message' => 'Erreur inscription']), 500);
        }

        $this->response(json_out(['ok' => true, 'id_utilisateur' => $newId]), 200);
    }

    private function connexion(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        $indicatif = $this->safeStr('indicatif_pays', 6) ?: '+227';
        $telNational = $this->safeStr('telephone_national', 30);
        $mdp = (string)($this->_request['mot_de_passe'] ?? '');

        if (!$telNational || !$mdp) {
            $this->response(json_out(['ok' => false, 'message' => 'Téléphone et mot de passe requis']), 400);
        }

        $telE164 = $this->normalizeE164($indicatif, $telNational);

        if (defined('LOG_CONNEXION') && LOG_CONNEXION) {
            error_log("[SONEF connexion] telE164=" . $telE164);
        }

        $stmt = $this->db->prepare("SELECT * FROM utilisateurs WHERE statut=1 AND telephone_e164=? LIMIT 1");
        $stmt->bind_param("s", $telE164);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (defined('LOG_CONNEXION') && LOG_CONNEXION) {
            error_log("[SONEF connexion] user trouvé=" . ($user ? 'oui id=' . $user['id_utilisateur'] : 'non'));
        }

        if (!$user || !password_verify($mdp, $user['mot_de_passe_hash'])) {
            $this->response(json_out(['ok' => false, 'message' => 'Identifiants invalides']), 401);
        }

        $token = random_token64();
        $exp = mysql_add_days(TOKEN_TTL_DAYS);
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

        $stmt = $this->db->prepare("INSERT INTO jetons_acces(id_utilisateur, jeton, date_expiration, ip, user_agent)
                                VALUES(?,?,?,?,?)");
        $stmt->bind_param("issss", $user['id_utilisateur'], $token, $exp, $ip, $ua);
        $stmt->execute();
        $stmt->close();

        $this->db->query("UPDATE utilisateurs SET dernier_login=NOW() WHERE id_utilisateur=" . (int)$user['id_utilisateur']);

        $this->response(json_out([
            'ok' => true,
            'token' => $token,
            'date_expiration' => $exp,
            'utilisateur' => [
                'id_utilisateur' => (int)$user['id_utilisateur'],
                'nom' => $user['nom'],
                'prenom' => $user['prenom'],
                'telephone_e164' => $user['telephone_e164'],
                'email' => $user['email']
            ]
        ]), 200);
    }


    private function profil(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);
        $u = $this->requireAuth();

        $this->response(json_out(['ok' => true, 'profil' => [
            'id_utilisateur' => (int)$u['id_utilisateur'],
            'nom' => $u['nom'],
            'prenom' => $u['prenom'],
            'telephone' => $u['telephone'],
            'email' => $u['email'],
            'photo_url' => $u['photo_url'],
        ]]), 200);
    }

    private function profil_update(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $nom = $this->safeStr('nom', 80) ?: $u['nom'];
        $prenom = $this->safeStr('prenom', 80) ?: $u['prenom'];
        $email = $this->safeStr('email', 120);

        $sql = "UPDATE utilisateurs SET nom=?, prenom=?, email=? WHERE id_utilisateur=?";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("sssi", $nom, $prenom, $email, $u['id_utilisateur']);
        $stmt->execute();
        $stmt->close();

        $this->response(json_out(['ok' => true]), 200);
    }
    private function profil_photo_upload(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        if (!isset($_FILES['photo']) || $_FILES['photo']['error'] !== UPLOAD_ERR_OK) {
            $this->response(json_out(['ok' => false, 'message' => 'Fichier photo requis']), 400);
        }

        $file = $_FILES['photo'];

        // sécurité mini
        $allowed = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'];
        $mime = mime_content_type($file['tmp_name']);
        if (!isset($allowed[$mime])) {
            $this->response(json_out(['ok' => false, 'message' => 'Format non supporté (jpg/png/webp)']), 415);
        }

        $ext = $allowed[$mime];
        $dir = __DIR__ . "/uploads/profils";
        if (!is_dir($dir)) @mkdir($dir, 0777, true);

        $name = "u" . $u['id_utilisateur'] . "_" . time() . "." . $ext;
        $dest = $dir . "/" . $name;

        if (!move_uploaded_file($file['tmp_name'], $dest)) {
            $this->response(json_out(['ok' => false, 'message' => 'Upload échoué']), 500);
        }

        // URL publique (adapte selon ton serveur)
        $url = "uploads/profils/" . $name;

        $stmt = $this->db->prepare("UPDATE utilisateurs SET photo_url=? WHERE id_utilisateur=?");
        $stmt->bind_param("si", $url, $u['id_utilisateur']);
        $stmt->execute();
        $stmt->close();

        $this->response(json_out(['ok' => true, 'photo_url' => $url]), 200);
    }


    private function push_token_enregistrer(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $token = $this->safeStr('expo_push_token', 255);
        if (!$token) $this->response(json_out(['ok' => false, 'message' => 'token requis']), 400);

        $sql = "UPDATE utilisateurs SET expo_push_token=? WHERE id_utilisateur=?";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("si", $token, $u['id_utilisateur']);
        $stmt->execute();
        $stmt->close();

        $this->response(json_out(['ok' => true]), 200);
    }

    // Dans ta classe API (api.php), ajoute cette méthode :

    private function trajets_tarifs(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $id_ville_depart  = isset($this->_request['id_ville_depart']) ? (int)$this->_request['id_ville_depart'] : 0;
        $id_ville_arrivee = isset($this->_request['id_ville_arrivee']) ? (int)$this->_request['id_ville_arrivee'] : 0;

        if ($id_ville_depart <= 0 || $id_ville_arrivee <= 0) {
            $this->response(json_out(['ok' => false, 'message' => 'Paramètres manquants.']), 400);
        }

        $sql = "
        SELECT
            t.id_trajet,
            vd.nom_ville AS ville_depart,
            va.nom_ville AS ville_arrivee,
            t.heure_depart,
            t.prix,
            b.immatriculation
        FROM trajets t
        INNER JOIN lignes l ON l.id_ligne = t.id_ligne
        INNER JOIN villes vd ON vd.id_ville = l.id_ville_depart
        INNER JOIN villes va ON va.id_ville = l.id_ville_arrivee
        LEFT JOIN bus b ON b.id_bus = t.id_bus
        WHERE l.id_ville_depart = ?
          AND l.id_ville_arrivee = ?
          AND (t.statut IS NULL OR t.statut <> 'annule')
        ORDER BY t.heure_depart ASC
    ";

        $stmt = $this->prepareOrFail($sql);
        $stmt->bind_param("ii", $id_ville_depart, $id_ville_arrivee);
        $stmt->execute();

        $res = $stmt->get_result();
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;

        $this->response(json_out(['ok' => true, 'trajets' => $rows]), 200);
    }

    // -------------------------
    // Référentiels
    // -------------------------
    private function villes_liste(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $res = $this->db->query("SELECT id_ville, nom_ville, pays FROM villes ORDER BY nom_ville ASC");
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $this->response(json_out(['ok' => true, 'villes' => $rows]), 200);
    }

    /**
     * Synchro villes : récupère la liste des axes (villes) depuis l'API externe SONEF
     * (http://162.43.192.47:9000/axes) et insère les noms manquants dans la table villes.
     *
     * Appel : POST api.php?rquest=synchro_villes
     * Optionnel : envoyer cle_synchro (body ou query) si SYNC_SECRET est défini dans config.php.
     */
    private function synchro_villes(): void
    {
        // --- 1. Accepter uniquement POST (évite qu'un simple lien ou un crawler déclenche la synchro) ---
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        // --- 2. Sécurité : si une clé de synchro est configurée, la vérifier ---
        if (defined('SYNC_SECRET') && SYNC_SECRET !== '') {
            $cle = trim((string)($this->_request['cle_synchro'] ?? ''));
            if ($cle !== SYNC_SECRET) {
                $this->response(json_out(['ok' => false, 'message' => 'Clé de synchro invalide']), 403);
            }
        }

        // --- 3. Appeler l'API externe pour récupérer la liste des axes (ex: ["ABALA", "ABIDJAN", ...]) ---
        $url = rtrim(EXTERNAL_API_BASE, '/') . '/axes';
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);  // renvoyer la réponse dans une variable au lieu de l'afficher
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);           // timeout 30 secondes
        // Envoyer le token Bearer si configuré (l'API externe renvoie 401 sans authentification)
        if (defined('EXTERNAL_API_TOKEN') && EXTERNAL_API_TOKEN !== '') {
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . EXTERNAL_API_TOKEN]);
        }
        $raw = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        // --- 4. Vérifier que l'appel HTTP a réussi (pas d'erreur réseau, pas de timeout) ---
        if ($raw === false || $err !== '') {
            $this->response(json_out(['ok' => false, 'message' => 'Erreur appel API externe', 'error' => $err]), 502);
        }

        // --- 5. Parser la réponse JSON : on attend un objet avec une clé "axes" (tableau de noms) ---
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['axes']) || !is_array($data['axes'])) {
            $this->response(json_out(['ok' => false, 'message' => 'Réponse API externe invalide (axes attendu)', 'http_code' => $httpCode]), 502);
        }

        $axes = $data['axes'];
        $nb_inseres = 0;

        // --- 6. Pour chaque nom d'axe reçu : l'ajouter en base s'il n'existe pas déjà ---
        foreach ($axes as $nom) {
            $nom = trim((string)$nom);
            if ($nom === '') continue;  // ignorer les chaînes vides

            // Vérifier si cette ville existe déjà dans la table villes (évite les doublons)
            $stmt = $this->db->prepare("SELECT 1 FROM villes WHERE nom_ville = ? LIMIT 1");
            $stmt->bind_param("s", $nom);
            $stmt->execute();
            $exists = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            // Si la ville n'existe pas, l'insérer (pays = NULL car l'API externe ne fournit pas le pays)
            if (!$exists) {
                $ins = $this->db->prepare("INSERT INTO villes (nom_ville, pays) VALUES (?, NULL)");
                $ins->bind_param("s", $nom);
                $ins->execute();
                $ins->close();
                $nb_inseres++;
            }
        }

        // --- 7. Répondre avec un résumé : nombre d'axes reçus et nombre de nouvelles lignes insérées ---
        $this->response(json_out([
            'ok' => true,
            'message' => 'Synchro villes terminée',
            'nb_axes_recus' => count($axes),
            'nb_inseres' => $nb_inseres
        ]), 200);
    }

    private function agences_liste(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $sql = "SELECT a.*, v.nom_ville, v.pays
                FROM agences a JOIN villes v ON v.id_ville=a.id_ville
                WHERE a.actif=1
                ORDER BY v.nom_ville, a.nom_agence";
        $res = $this->db->query($sql);
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $this->response(json_out(['ok' => true, 'agences' => $rows]), 200);
    }

    private function actualites_liste(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $cat = $this->safeStr('categorie', 40); // optionnel

        if ($cat) {
            $stmt = $this->db->prepare("
            SELECT id_actualite, titre, date_publication,image_url
            FROM actualites
            WHERE actif=1 AND categorie=?
            ORDER BY date_publication DESC
            LIMIT 50
        ");
            $stmt->bind_param("s", $cat);
            $stmt->execute();
            $res = $stmt->get_result();
        } else {
            $res = $this->db->query("
            SELECT id_actualite, titre, date_publication,image_url
            FROM actualites
            WHERE actif=1
            ORDER BY date_publication DESC
            LIMIT 50
        ");
        }

        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        if (isset($stmt)) $stmt->close();

        $this->response(json_out(['ok' => true, 'actualites' => $rows]), 200);
    }

    private function actualite_detail(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $id = (int)($this->safeStr('id', 20));
        if (!$id) $this->response(json_out(['ok' => false, 'message' => 'ID manquant']), 400);

        $stmt = $this->db->prepare("
        SELECT id_actualite, titre, date_publication, contenu,image_url
        FROM actualites
        WHERE actif=1 AND id_actualite=?
        LIMIT 1
    ");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $res = $stmt->get_result();
        $row = $res->fetch_assoc();
        $stmt->close();

        if (!$row) $this->response(json_out(['ok' => false, 'message' => 'Actualité introuvable']), 404);

        $this->response(json_out(['ok' => true, 'actualite' => $row]), 200);
    }



    // -------------------------
    // Billetterie (recherche, réservation, paiement)
    // -------------------------
    private function trajets_rechercher(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $id_dep = (int)($this->_request['id_ville_depart'] ?? 0);
        $id_arr = (int)($this->_request['id_ville_arrivee'] ?? 0);
        $date = $this->safeStr('date_depart', 10);
        if (!$date) $date = $this->safeStr('date', 10); // compat si une ancienne page envoie "date"

        $heure = $this->safeStr('heure_depart', 5); // optionnel

        if (!$id_dep || !$id_arr || !$date) {
            $this->response(json_out(['ok' => false, 'message' => 'Paramètres requis']), 400);
        }

        $sql = "SELECT t.*, l.nom_ligne, b.immatriculation, b.capacite
            FROM trajets t
            JOIN lignes l ON l.id_ligne=t.id_ligne
            JOIN bus b ON b.id_bus=t.id_bus
            WHERE l.id_ville_depart=? AND l.id_ville_arrivee=?
              AND t.statut <> 'annule'
               ";

        $types = "ii";
        $params = [$id_dep, $id_arr];

        if ($heure) {
            $sql .= " AND TIME_FORMAT(t.heure_depart, '%H:%i') = ?";
            $types .= "s";
            $params[] = $heure;
        }

        $sql .= " ORDER BY t.heure_depart ASC";

        $stmt = $this->prepareOrFail($sql, "TRAJETS_RECHERCHER");
        $stmt->bind_param($types, ...$params);
        $stmt->execute();

        $res = $stmt->get_result();
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $stmt->close();

        $this->response(json_out(['ok' => true, 'trajets' => $rows]), 200);
    }


    private function prepareOrFail(string $sql, string $ctx = ''): mysqli_stmt
    {
        $stmt = $this->db->prepare($sql);
        if (!$stmt) {
            $this->response(json_out([
                'ok' => false,
                'message' => 'Prepare failed',
                'ctx' => $ctx,
                'sql' => $sql,
                'error' => $this->db->error
            ]), 500);
        }
        return $stmt;
    }


    private function billet_reserver(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);

        $u = $this->requireAuth();

        $data = json_decode(file_get_contents("php://input"), true);

        $id_trajet   = (int)($data['id_trajet'] ?? 0);
        $nb_places   = (int)($data['nb_places'] ?? 1);
        $type_voyage = strtoupper(trim((string)($data['type_voyage'] ?? "AS")));
        $date_retour = $data['date_retour'] ?? null;

        $benef_prenom = trim((string)($data['benef_prenom'] ?? ""));
        $benef_nom    = trim((string)($data['benef_nom'] ?? ""));
        $benef_tel    = trim((string)($data['benef_tel'] ?? ""));

        if (!$id_trajet) {
            $this->response(json_out(['ok' => false, 'message' => 'id_trajet requis']), 400);
        }

        if ($nb_places < 1) $nb_places = 1;
        if ($nb_places > 9) $nb_places = 9;

        if (!in_array($type_voyage, ['AS', 'AR'], true)) $type_voyage = 'AS';

        if ($type_voyage === "AR" && empty($date_retour)) {
            $this->response(json_out(['ok' => false, 'message' => "date_retour requise pour un aller-retour"]), 400);
        }

        $pour_autrui = (!empty($benef_prenom) || !empty($benef_nom) || !empty($benef_tel)) ? 1 : 0;
        if ($pour_autrui) {
            if (empty($benef_prenom) || empty($benef_nom) || empty($benef_tel)) {
                $this->response(json_out(['ok' => false, 'message' => "Nom, prénom et téléphone du bénéficiaire requis"]), 400);
            }
        }

        // ✅ pour éviter des soucis quand date_retour = null
        $date_retour_sql = $date_retour ?: null;

        $this->db->begin_transaction();

        try {
            // 1) LOCK trajet
            $sqlT = "SELECT prix, places_disponibles
                 FROM trajets
                 WHERE id_trajet=? AND statut <> 'annule'
                 FOR UPDATE";

            $stmtT = $this->prepareOrFail($sqlT, "LOCK_TRAJET");
            $stmtT->bind_param("i", $id_trajet);
            $stmtT->execute();
            $stmtT->bind_result($prix_db, $dispo_db);

            if (!$stmtT->fetch()) {
                $stmtT->close();
                $this->db->rollback();
                $this->response(json_out(['ok' => false, 'message' => 'Trajet introuvable']), 404);
            }
            $stmtT->close();

            $prix  = (int)$prix_db;
            $dispo = (int)$dispo_db;

            if ($dispo < $nb_places) {
                $this->db->rollback();
                $this->response(json_out(['ok' => false, 'message' => "Places insuffisantes (dispo: $dispo)"]), 400);
            }

            $montant = $prix * $nb_places;

            // 2) Générer code billet unique + vérif (sans get_result)
            $code_billet = null;

            for ($i = 0; $i < 5; $i++) {
                $code_billet = 'B' . date('ymd') . strtoupper(substr(bin2hex(random_bytes(5)), 0, 10));

                $stmtC = $this->prepareOrFail("SELECT 1 FROM billets WHERE code_billet=? LIMIT 1", "CHECK_CODE");
                $stmtC->bind_param("s", $code_billet);
                $stmtC->execute();
                $stmtC->bind_result($one);
                $exists = $stmtC->fetch();
                $stmtC->close();

                if (!$exists) break;
            }

            if (!$code_billet) {
                $this->db->rollback();
                $this->response(json_out(['ok' => false, 'message' => 'Impossible de générer un code billet']), 500);
            }

            // 3) Insert billet
            $qr_payload = json_out([
                'code_billet' => $code_billet,
                'id_billet'   => null,
                'id_trajet'   => $id_trajet,
                'nb_places'   => $nb_places,
                'montant_total'     => $montant,
            ]);

            $sqlB = "INSERT INTO billets
            (id_utilisateur, id_trajet, type_voyage, nb_places, pour_autrui,
             beneficiaire_nom, beneficiaire_prenom, beneficiaire_phone,
             code_billet, montant_total, statut, qr_payload, date_retour)
            VALUES (?,?,?,?,?,?,?,?,?,?, 'reserve', ?, ?)";

            $stmtB = $this->prepareOrFail($sqlB, "INSERT_BILLET");

            $id_user = (int)$u['id_utilisateur'];

            // 12 placeholders => 12 types
            $stmtB->bind_param(
                "iisiissssiss",
                $id_user,
                $id_trajet,
                $type_voyage,
                $nb_places,
                $pour_autrui,
                $benef_nom,
                $benef_prenom,
                $benef_tel,
                $code_billet,
                $montant,
                $qr_payload,
                $date_retour_sql
            );

            $stmtB->execute();
            $id_billet = (int)$stmtB->insert_id;
            $stmtB->close();

            // 4) Update qr_payload
            $qr_payload2 = json_out([
                'code_billet' => $code_billet,
                'id_billet'   => $id_billet,
                'id_trajet'   => $id_trajet,
                'nb_places'   => $nb_places,
                'montant'     => $montant,
            ]);

            $stmtQ = $this->prepareOrFail("UPDATE billets SET qr_payload=? WHERE id_billet=?", "UPDATE_QR");
            $stmtQ->bind_param("si", $qr_payload2, $id_billet);
            $stmtQ->execute();
            $stmtQ->close();

            // 5) Décrémenter les places
            $stmtU = $this->prepareOrFail(
                "UPDATE trajets SET places_disponibles = places_disponibles - ? WHERE id_trajet=?",
                "UPDATE_PLACES"
            );
            $stmtU->bind_param("ii", $nb_places, $id_trajet);
            $stmtU->execute();
            $stmtU->close();

            $this->db->commit();

            $this->response(json_out([
                'ok' => true,
                'id_billet' => $id_billet,
                'code_billet' => $code_billet,
                'nb_places' => $nb_places,
                'prix' => $prix,
                'montant_total' => $montant
            ]), 200);
        } catch (Throwable $e) {
            $this->db->rollback();
            $this->response(json_out([
                'ok' => false,
                'message' => 'Erreur serveur: ' . $e->getMessage()
            ]), 500);
        }
    }



    private function lignes_villes_depart(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $sql = "SELECT DISTINCT v.id_ville, v.nom_ville, v.pays
            FROM lignes l
            JOIN villes v ON v.id_ville = l.id_ville_depart
            WHERE l.actif=1
            ORDER BY v.nom_ville ASC";
        $res = $this->db->query($sql);

        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;

        $this->response(json_out(['ok' => true, 'villes_depart' => $rows]), 200);
    }

    private function lignes_villes_arrivee(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $id_dep = (int)($this->_request['id_ville_depart'] ?? 0);
        if (!$id_dep) $this->response(json_out(['ok' => false, 'message' => 'id_ville_depart requis']), 400);

        $sql = "SELECT DISTINCT v.id_ville, v.nom_ville, v.pays
            FROM lignes l
            JOIN villes v ON v.id_ville = l.id_ville_arrivee
            WHERE l.actif=1 AND l.id_ville_depart=?
            ORDER BY v.nom_ville ASC";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $id_dep);
        $stmt->execute();
        $res = $stmt->get_result();

        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $stmt->close();

        $this->response(json_out(['ok' => true, 'villes_arrivee' => $rows]), 200);
    }


    private function billets_recherche_tel(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        // Auth (client connecté)
        $me = $this->requireAuth();

        // Paramètres possibles
        $telE164 = $this->safeStr('telephone_e164', 40);
        $indicatif = $this->safeStr('indicatif_pays', 6) ?: ($me['indicatif_pays'] ?? '+227');
        $telNat = $this->safeStr('telephone_national', 30);

        // Si on ne fournit rien, on prend le téléphone du user connecté
        if ($telE164 === '') {
            if ($telNat !== '') {
                $telE164 = $this->normalizeE164($indicatif, $telNat);
            } else {
                $telE164 = (string)($me['telephone_e164'] ?: $me['telephone']);
            }
        }

        if ($telE164 === '') {
            $this->response(json_out(['ok' => false, 'message' => 'Téléphone requis']), 400);
        }

        // Normalisation "digits only" pour comparer facilement
        $needleDigits = preg_replace('/\D+/', '', $telE164);

        // ⚠️ Dans ta DB: billets.montant_total (pas montantl)
        $sql = "SELECT
                b.id_billet,
                b.code_billet,
                b.nb_places,
                b.type_voyage,
                b.montant_total AS montant_total,
                b.statut AS billet_statut,
                b.pour_autrui,
                b.beneficiaire_nom,
                b.beneficiaire_prenom,
                b.beneficiaire_phone,
                b.date_creation,

                t.id_trajet,
                t.date_depart,
                t.heure_depart,
                t.prix,

                vd.id_ville AS id_ville_depart,
                va.id_ville AS id_ville_arrivee,
                vd.nom_ville AS ville_depart,
                va.nom_ville AS ville_arrivee,
                l.nom_ligne,
                bus.immatriculation,

                (
                    SELECT p.statut
                    FROM paiements p
                    WHERE p.id_billet = b.id_billet
                    ORDER BY p.id_paiement DESC
                    LIMIT 1
                ) AS paiement_statut,

                (
                    SELECT p.date_validation
                    FROM paiements p
                    WHERE p.id_billet = b.id_billet
                    ORDER BY p.id_paiement DESC
                    LIMIT 1
                ) AS date_paiement

            FROM billets b
            JOIN trajets t ON t.id_trajet = b.id_trajet
            JOIN lignes l ON l.id_ligne = t.id_ligne
            JOIN villes vd ON vd.id_ville = l.id_ville_depart
            JOIN villes va ON va.id_ville = l.id_ville_arrivee
            LEFT JOIN bus ON bus.id_bus = t.id_bus
            LEFT JOIN utilisateurs u ON u.id_utilisateur = b.id_utilisateur

            WHERE
                (
                    b.pour_autrui = 1
                    AND REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(b.beneficiaire_phone,'+',''),' ',''),'-',''),'(',''),')','') = ?
                )
                OR
                (
                    b.pour_autrui = 0
                    AND REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(u.telephone_e164,'+',''),' ',''),'-',''),'(',''),')','') = ?
                )

            ORDER BY b.id_billet DESC
            LIMIT 200";

        $st = $this->db->prepare($sql);
        if (!$st) {
            $this->response(json_out(['ok' => false, 'message' => 'Prepare failed', 'error' => $this->db->error]), 500);
        }

        $st->bind_param("ss", $needleDigits, $needleDigits);
        $st->execute();
        $res = $st->get_result();

        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $st->close();

        $this->response(json_out(['ok' => true, 'telephone_e164' => $telE164, 'billets' => $rows]), 200);
    }

    // -------------------------
    // Mes billets / réservations (client lié au téléphone du user connecté)
    // rquest=billets_mes
    // -------------------------
    private function billets_mes(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);
        $u = $this->requireAuth();

        $sql = "SELECT
                b.id_billet,
                b.code_billet,
                b.nb_places,
                b.type_voyage,
                b.montant_total as montant,
                b.statut AS billet_statut,
                b.date_creation,

                t.id_trajet,
                t.date_depart,
                t.heure_depart,
                t.prix,
                t.places_disponibles,
 vd.id_ville AS id_ville_depart,
  va.id_ville AS id_ville_arrivee,
  vd.nom_ville AS ville_depart,
  va.nom_ville AS ville_arrivee,
                l.nom_ligne,
               
                bus.immatriculation,

                (
                    SELECT p.statut
                    FROM paiements p
                    WHERE p.id_billet = b.id_billet
                    ORDER BY p.id_paiement DESC
                    LIMIT 1
                ) AS paiement_statut

            FROM billets b
            JOIN trajets t ON t.id_trajet = b.id_trajet
            JOIN lignes l ON l.id_ligne = t.id_ligne
            JOIN villes vd ON vd.id_ville = l.id_ville_depart
            JOIN villes va ON va.id_ville = l.id_ville_arrivee
            LEFT JOIN bus ON bus.id_bus = t.id_bus
            WHERE b.id_utilisateur = ?
            ORDER BY b.id_billet DESC
            LIMIT 200";

        $st = $this->prepareOrFail($sql);
        $st->bind_param("i", $u['id_utilisateur']);
        $st->execute();
        $res = $st->get_result();

        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $st->close();

        $this->response(json_out(['ok' => true, 'billets' => $rows]));
    }


    private function billet_reprogrammer(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $idBillet = (int)($this->_request['id_billet'] ?? 0);
        $dateDepart = trim((string)($this->_request['date_depart'] ?? ''));
        $heureDepart = trim((string)($this->_request['heure_depart'] ?? ''));

        if ($idBillet <= 0 || $dateDepart === '' || $heureDepart === '') {
            $this->response(json_out(['ok' => false, 'message' => 'Champs manquants']), 400);
        }

        // 1) Charger billet + trajet actuel
        $sqlB = "SELECT b.id_billet, b.id_utilisateur, b.id_trajet, b.nb_places, b.statut,
                    t.id_ligne
             FROM billets b
             JOIN trajets t ON t.id_trajet = b.id_trajet
             WHERE b.id_billet = ?
             LIMIT 1";
        $stB = $this->prepareOrFail($sqlB);
        $stB->bind_param("i", $idBillet);
        $stB->execute();
        $billet = $stB->get_result()->fetch_assoc();
        $stB->close();

        if (!$billet) $this->response(json_out(['ok' => false, 'message' => 'Billet introuvable']), 404);
        if ((int)$billet['id_utilisateur'] !== (int)$u['id_utilisateur']) {
            $this->response(json_out(['ok' => false, 'message' => 'Accès refusé']), 403);
        }


        $oldTrajetId = (int)$billet['id_trajet'];
        $idLigne = (int)$billet['id_ligne'];
        $nbPlaces = (int)$billet['nb_places'];

        $this->db->begin_transaction();
        try {
            // 2) Trouver nouveau trajet (même ligne + date/heure)
            $sqlT = "SELECT id_trajet, places_disponibles
                 FROM trajets
                 WHERE id_ligne = ?
                   AND date_depart = ?
                   AND TIME_FORMAT(heure_depart, '%H:%i') = ?
                   AND statut <> 'annule'
                 FOR UPDATE
                 LIMIT 1";
            $stT = $this->prepareOrFail($sqlT);
            $stT->bind_param("iss", $idLigne, $dateDepart, $heureDepart);
            $stT->execute();
            $newTrajet = $stT->get_result()->fetch_assoc();
            $stT->close();

            if (!$newTrajet) {
                $this->db->rollback();
                $this->response(json_out(['ok' => false, 'message' => "Aucun bus trouvé pour cette date/heure."]), 404);
            }

            $newTrajetId = (int)$newTrajet['id_trajet'];
            if ($newTrajetId === $oldTrajetId) {
                $this->db->rollback();
                $this->response(json_out(['ok' => false, 'message' => "Même trajet sélectionné."]), 400);
            }

            if ((int)$newTrajet['places_disponibles'] < $nbPlaces) {
                $this->db->rollback();
                $this->response(json_out(['ok' => false, 'message' => "Places insuffisantes sur le nouveau trajet."]), 400);
            }

            // 3) Ajuster places: rendre à l'ancien, prendre sur le nouveau
            $st1 = $this->prepareOrFail("UPDATE trajets SET places_disponibles = places_disponibles + ? WHERE id_trajet=?");
            $st1->bind_param("ii", $nbPlaces, $oldTrajetId);
            $st1->execute();
            $st1->close();

            $st2 = $this->prepareOrFail("UPDATE trajets SET places_disponibles = places_disponibles - ? WHERE id_trajet=?");
            $st2->bind_param("ii", $nbPlaces, $newTrajetId);
            $st2->execute();
            $st2->close();

            // 4) Update billet
            $stU = $this->prepareOrFail("UPDATE billets SET id_trajet=? WHERE id_billet=? LIMIT 1", "UPDATE_BILLET");
            $stU->bind_param("ii", $newTrajetId, $idBillet);

            $stU->execute();
            $stU->close();

            $this->db->commit();

            $this->response(json_out([
                'ok' => true,
                'message' => 'Billet reprogrammé avec succès',
                'id_trajet' => $newTrajetId,
                'date_depart' => $dateDepart,
                'heure_depart' => $heureDepart
            ]));
        } catch (Throwable $e) {
            $this->db->rollback();
            $this->response(json_out(['ok' => false, 'message' => 'Erreur reprogrammation']), 500);
        }
    }


    // Paiement init (stub) : renvoie une URL fictive à ouvrir côté mobile
    private function paiement_init(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $id_billet = $this->safeInt('id_billet');
        $fournisseur = strtoupper($this->safeStr('fournisseur', 20)); // NITA/AMANA

        if (!$id_billet || !in_array($fournisseur, ['NITA', 'AMANA'], true)) {
            $this->response(json_out(['ok' => false, 'message' => 'Paramètres invalides']), 400);
        }

        // récup billet
        $stmt = $this->db->prepare("SELECT montant_total AS montant, statut FROM billets WHERE id_billet=? AND id_utilisateur=? LIMIT 1");
        $stmt->bind_param("ii", $id_billet, $u['id_utilisateur']);
        $stmt->execute();
        $billet = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$billet) $this->response(json_out(['ok' => false, 'message' => 'Billet introuvable']), 404);
        if ($billet['statut'] === 'paye') $this->response(json_out(['ok' => true, 'message' => 'Déjà payé']), 200);

        $ref_interne = 'SONEF-' . strtoupper(substr(bin2hex(random_bytes(6)), 0, 12));

        $payloadInit = [
            'montant' => (int)$billet['montant'],
            'reference' => $ref_interne,
            'id_billet' => $id_billet,
            'fournisseur' => $fournisseur
        ];

        $stmt = $this->db->prepare("INSERT INTO paiements(id_utilisateur,id_billet,fournisseur,reference_interne,montant,payload_init)
                                    VALUES(?,?,?,?,?,?)");
        $payloadJson = json_out($payloadInit);
        $stmt->bind_param("iissis", $u['id_utilisateur'], $id_billet, $fournisseur, $ref_interne, $payloadInit['montant'], $payloadJson);
        $stmt->execute();
        $id_paiement = (int)$stmt->insert_id;
        $stmt->close();

        // URL “stub” locale : en prod = redirection vers fournisseur
        $url_stub = sprintf(
            "http://127.0.0.1:8000/api.php?rquest=paiement_stub_ui&id_paiement=%d&result=succes",
            $id_paiement
        );

        // Le flux “init -> redirection -> callback -> validation billet” est exactement celui décrit dans le PDF. :contentReference[oaicite:8]{index=8}
        $this->response(json_out([
            'ok' => true,
            'id_paiement' => $id_paiement,
            'reference_interne' => $ref_interne,
            'url_paiement' => $url_stub
        ]), 200);
    }

    // Page HTML simple pour simuler NITA/AMANA (dev uniquement)
    private function paiement_stub_ui(): void
    {
        // On sort volontairement du JSON ici (dev)
        $id = (int)($_GET['id_paiement'] ?? 0);
        $result = $_GET['result'] ?? 'succes'; // succes|echec
        $callback = "http://127.0.0.1:8000/api.php?rquest=paiement_callback&id_paiement={$id}&statut={$result}";

        header("Content-Type: text/html; charset=utf-8");
        echo "<h2>Stub Paiement (DEV)</h2>";
        echo "<p>ID paiement: {$id}</p>";
        echo "<p><a href='{$callback}'>Confirmer ({$result})</a></p>";
        exit;
    }

    // Callback fournisseur (simulé)
    private function paiement_callback(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $id_paiement = (int)($_GET['id_paiement'] ?? 0);
        $statut = $_GET['statut'] ?? 'succes';

        $stmt = $this->db->prepare("SELECT * FROM paiements WHERE id_paiement=? LIMIT 1");
        $stmt->bind_param("i", $id_paiement);
        $stmt->execute();
        $p = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$p) $this->response(json_out(['ok' => false, 'message' => 'Paiement introuvable']), 404);

        $payloadCb = json_out([
            'id_paiement' => $id_paiement,
            'statut' => $statut,
            'reference_fournisseur' => 'FOURN-' . strtoupper(substr(bin2hex(random_bytes(5)), 0, 10)),
        ]);

        if ($statut === 'succes') {
            // valider paiement + billet + notification
            $this->db->begin_transaction();
            try {
                $stmt = $this->db->prepare("UPDATE paiements SET statut='succes', payload_callback=?, date_validation=NOW()
                                            WHERE id_paiement=? AND statut='initie'");
                $stmt->bind_param("si", $payloadCb, $id_paiement);
                $stmt->execute();
                $stmt->close();

                $stmt = $this->db->prepare("UPDATE billets SET statut='paye', date_modif=NOW()
                                            WHERE id_billet=?");
                $stmt->bind_param("i", $p['id_billet']);
                $stmt->execute();
                $stmt->close();

                $stmt = $this->db->prepare("INSERT INTO notifications(id_utilisateur,type_notification,titre,message,donnees)
                                            VALUES(?, 'billet', 'Paiement confirmé', 'Votre billet est payé et disponible.', ?)");
                $donnees = json_out(['id_billet' => (int)$p['id_billet'], 'ref' => $p['reference_interne']]);
                $stmt->bind_param("is", $p['id_utilisateur'], $donnees);
                $stmt->execute();
                $stmt->close();

                $this->db->commit();
            } catch (Throwable $e) {
                $this->db->rollback();
                $this->response(json_out(['ok' => false, 'message' => 'Erreur validation']), 500);
            }
        } else {
            $stmt = $this->db->prepare("UPDATE paiements SET statut='echec', payload_callback=? WHERE id_paiement=?");
            $stmt->bind_param("si", $payloadCb, $id_paiement);
            $stmt->execute();
            $stmt->close();
        }

        // Dev: simple retour
        $this->response(json_out(['ok' => true, 'id_paiement' => $id_paiement, 'statut' => $statut]), 200);
    }

    // -------------------------
    // Colis (création / suivi)
    // -------------------------
    private function colis_creer(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $nom_dest = $this->safeStr('nom_destinataire', 160);
        $tel_dest = $this->safeStr('telephone_destinataire', 30);
        $ag_depot = $this->safeInt('id_agence_depot');
        $ag_retrait = $this->safeInt('id_agence_retrait');
        $desc = $this->safeStr('description_colis', 255);
        $poids = (float)($this->_request['poids_kg'] ?? 0);

        if (!$nom_dest || !$tel_dest || !$ag_depot || !$ag_retrait) {
            $this->response(json_out(['ok' => false, 'message' => 'Champs requis manquants']), 400);
        }

        $code = 'C' . strtoupper(substr(bin2hex(random_bytes(5)), 0, 10));

        $stmt = $this->db->prepare("INSERT INTO colis(id_expediteur, nom_destinataire, telephone_destinataire, id_agence_depot, id_agence_retrait, description_colis, poids_kg, code_suivi, statut)
                                    VALUES(?,?,?,?,?,?,?,?, 'depot')");
        $stmt->bind_param("issii sds", $u['id_utilisateur'], $nom_dest, $tel_dest, $ag_depot, $ag_retrait, $desc, $poids, $code);
        // Correction bind_param format: rebuild properly
        $stmt->close();

        $sql = "INSERT INTO colis(id_expediteur, nom_destinataire, telephone_destinataire, id_agence_depot, id_agence_retrait, description_colis, poids_kg, code_suivi, statut)
                VALUES(?,?,?,?,?,?,?,?, 'depot')";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("issii sds", $u['id_utilisateur'], $nom_dest, $tel_dest, $ag_depot, $ag_retrait, $desc, $poids, $code);
        // php mysqli bind_param doesn't allow spaces in types, so:
        $stmt->close();

        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("issiisds", $u['id_utilisateur'], $nom_dest, $tel_dest, $ag_depot, $ag_retrait, $desc, $poids, $code);
        $stmt->execute();
        $id_colis = (int)$stmt->insert_id;
        $stmt->close();

        $stmt = $this->db->prepare("INSERT INTO colis_suivi(id_colis, statut, commentaire, id_agence)
                                    VALUES(?, 'depot', 'Colis déposé', ?)");
        $stmt->bind_param("ii", $id_colis, $ag_depot);
        $stmt->execute();
        $stmt->close();

        $this->response(json_out(['ok' => true, 'id_colis' => $id_colis, 'code_suivi' => $code]), 200);
    }

    private function colis_suivre(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);

        $code = $this->safeStr('code_suivi', 20);
        if (!$code) $this->response(json_out(['ok' => false, 'message' => 'code requis']), 400);

        $stmt = $this->db->prepare("SELECT c.*, ad.nom_agence AS agence_depot, ar.nom_agence AS agence_retrait
                                    FROM colis c
                                    JOIN agences ad ON ad.id_agence=c.id_agence_depot
                                    JOIN agences ar ON ar.id_agence=c.id_agence_retrait
                                    WHERE c.code_suivi=? LIMIT 1");
        $stmt->bind_param("s", $code);
        $stmt->execute();
        $colis = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$colis) $this->response(json_out(['ok' => false, 'message' => 'introuvable']), 404);

        $stmt = $this->db->prepare("SELECT s.*, a.nom_agence
                                    FROM colis_suivi s
                                    LEFT JOIN agences a ON a.id_agence=s.id_agence
                                    WHERE s.id_colis=? ORDER BY s.date_evenement ASC");
        $stmt->bind_param("i", $colis['id_colis']);
        $stmt->execute();
        $res = $stmt->get_result();
        $suivi = [];
        while ($r = $res->fetch_assoc()) $suivi[] = $r;
        $stmt->close();

        $this->response(json_out(['ok' => true, 'colis' => $colis, 'suivi' => $suivi]), 200);
    }

    private function colis_mes(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);
        $u = $this->requireAuth();

        $stmt = $this->db->prepare("SELECT * FROM colis WHERE id_expediteur=? ORDER BY date_creation DESC LIMIT 100");
        $stmt->bind_param("i", $u['id_utilisateur']);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $stmt->close();

        $this->response(json_out(['ok' => true, 'colis' => $rows]), 200);
    }

    // -------------------------
    // Notifications
    // -------------------------
    private function notifications_liste(): void
    {
        if ($this->get_request_method() !== "GET") $this->response('', 406);
        $u = $this->requireAuth();

        $stmt = $this->db->prepare("SELECT * FROM notifications WHERE id_utilisateur=? ORDER BY date_creation DESC LIMIT 100");
        $stmt->bind_param("i", $u['id_utilisateur']);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = [];
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $stmt->close();

        $this->response(json_out(['ok' => true, 'notifications' => $rows]), 200);
    }

    private function notification_lue(): void
    {
        if ($this->get_request_method() !== "POST") $this->response('', 406);
        $u = $this->requireAuth();

        $id = $this->safeInt('id_notification');
        if (!$id) $this->response(json_out(['ok' => false, 'message' => 'id requis']), 400);

        $stmt = $this->db->prepare("UPDATE notifications SET lu=1 WHERE id_notification=? AND id_utilisateur=?");
        $stmt->bind_param("ii", $id, $u['id_utilisateur']);
        $stmt->execute();
        $stmt->close();

        $this->response(json_out(['ok' => true]), 200);
    }
}

$api = new API();
$api->processApi();
