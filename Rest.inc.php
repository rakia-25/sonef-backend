<?php
// backend/Rest.inc.php

class REST
{
    protected $_request = [];

    public function __construct()
    {
        $this->inputs();
    }

    private function inputs(): void
    {
        $method = $this->get_request_method();

        // Query string (GET)
        $this->_request = $_REQUEST ?? [];

        // JSON body (POST/PUT)
        if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $raw = file_get_contents("php://input");
            $json = json_decode($raw, true);
            if (is_array($json)) {
                $this->_request = array_merge($this->_request, $json);
            }
        }
    }

    public function get_request_method(): string
    {
        return $_SERVER['REQUEST_METHOD'] ?? 'GET';
    }

    protected function response($data, int $status = 200): void
    {
        http_response_code($status);
        header("Content-Type: application/json; charset=utf-8");
        echo $data;
        exit;
    }
}
