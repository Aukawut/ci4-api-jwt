<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\Request;
use Exception;
use PDOException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class UserController extends BaseController
{
    protected $db;
    protected $key;
    public function __construct()
    {
        $this->db   = db_connect();
        $this->key =  getenv('JWT_SECRET');
    }
    public function index()
    {

        $q =  $this->db->query("SELECT * FROM tb_users");
        $results = $q->getResult();
        return response()->setJSON(["results" => $results]);

        //
    }
    public function byId($id)
    {
        $q = $this->db->query("SELECT * FROM tb_users WHERE id = ?", [$id]);
        $results = $q->getResult();
        if ($results) {
            return response()->setJSON(["results" => $results]);
        } else {
            return response()->setJSON(["results" => 'Users not founded!']);
        }
    }
    public function store()
    {
        try {
            $request = service('request');
            $body = $request->getJSON(true); // Assuming request body is in JSON format

            // Get the value of the "name" key

            $password = $body['password'];
            $email = preg_replace('/\s+/', '', $body['email']);
            $address = $body['address'];
            $hash = password_hash($password, PASSWORD_BCRYPT);


            $q2 = $this->db->query("SELECT * FROM tb_users WHERE email = ?", [$email]);
            $results = $q2->getResult();

            if (count($results) > 0) {

                return response()->setJSON(["err" => true, "message" => "Duplicate email!"]);
            } else {
                $q = $this->db->query("INSERT INTO tb_users (email,password,address) VALUES (?,?,?)", [$email, $hash, $address]);
                if ($q) {
                    return response()->setJSON(["err" => false, "message" => "Data inserted!"]);
                }
            }
        } catch (PDOException $e) {
            return response()->setJSON(["err" => true, "message" => $e->getMessage()]);
        }
    }
    public function update($id)
    {
        try {
            $request = service('request');
            $body = $request->getJSON(true);
            $address = $body['address'];
            $select = $this->db->query("SELECT * FROM tb_users WHERE id = ?", [$id]);
            $result = $select->getResult();
            if ($result) {
                // $hash_password = $result[0]->password;
                $q = $this->db->query("UPDATE tb_users SET address = ? WHERE id = ?", [$address, $id]);
                if ($q) {
                    return response()->setJSON(["err" => false, "message" => "Data updated!"]);
                }
            } else {

                return response()->setJSON(["err" => true, "message" => "User not fonded!"]);
            }
        } catch (PDOException $e) {
            return response()->setJSON(["err" => true, "message" => $e->getMessage()]);
        }
    }
    public function login()
    {
        try {

            $request = service('request');
            $body = $request->getJSON(true);
            $password = $body['password'];
            $email = preg_replace('/\s+/', '', $body['email']);
            $iat = time(); // current timestamp value
            $exp = $iat + 3600;
            $stmt  = $this->db->query("SELECT * FROM tb_users WHERE email = ?", [$email]);
            $result = $stmt->getResult();

            if ($result) {
                $hash = $result[0]->password;
                $payload = array(
                    "iss" => "F Service JWT",
                    "aud" => "F Dev",
                    "sub" => "JWT",
                    "iat" => $iat, //Time the JWT issued at
                    "exp" => $exp, // Expiration time of token
                    "email" => $result[0]->email,
                );
                $token = JWT::encode($payload, $this->key, 'HS256');
                if (password_verify($password, $hash)) {
                    return response()->setJSON(["err" => false, "message" => "Login successfully!", "token" => $token]);
                } else {
                    return response()->setJSON(["err" => true, "message" => "Email or Password invalid!"]);
                }
            } else {

                return response()->setJSON(["err" => true, "message" => "Email or Password invalid!"]);
            }
        } catch (PDOException $e) {
            return response()->setJSON(["err" => true, "message" => $e->getMessage()]);
        }
    }
    public function Auth()
    {
        $headers = getallheaders();
        $authorizationHeader = $headers['Authorization'];

        // Extract the bearer token from the Authorization header
        if (preg_match('/Bearer\s(\S+)/', $authorizationHeader, $matches)) {
            $token = $matches[1];

            if (is_null($token) || empty($token)) {
                return response()->setJSON(["err" => true, "message" => "Token is required!"]);
            } else {
                try {
                    $decoded = JWT::decode($token, new Key($this->key, 'HS256'));
                    return response()->setJSON(["err" => false, "decoded" => $decoded]);
                } catch (Exception $e) {
                    return response()->setJSON($e->getMessage());
                }
            }
        } else {
            // Authorization header or bearer token is missing
            return response()->setJSON(["err" => true, "message" => "Bearer token is missing!"]);
        }
    }
}
