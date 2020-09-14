<?php
    class JWT {
        private function base64url_encode($data) {
            return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        }

        private function base64url_decode($data) { 
            return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT)); 
        }

        public function sign($payload, $secret, $options = []) {
            $header = [
                'alg' => 'HS256',
                'typ' => 'JWT'
            ];
            $headerJSON = json_encode($header);
            $headerBase64 = $this->base64url_encode($headerJSON);

            $payloadFromOptions = [];
            if(count($options)) {
                if(isset($options['notBefore'])) {
                    $payloadFromOptions["nbf"] = time() + $options['notBefore'];
                }
                if(isset($options['expiresIn'])) {
                    $payloadFromOptions["exp"] = time() + $options['expiresIn'];
                }
            }
            $payloadWithOptions = array_merge($payload, $payloadFromOptions);

            $payloadJSON = json_encode($payloadWithOptions);
            $payloadBase64 = $this->base64url_encode($payloadJSON);

            $signature = hash_hmac('SHA256', "$headerBase64.$payloadBase64", $secret, true);
            $signatureBase64 = $this->base64url_encode($signature);

            return "$headerBase64.$payloadBase64.$signatureBase64";
        }

        public function verify($token, $secret) {
            try {
                $tokenArray = explode('.', $token);
                $headerBase64 = $tokenArray[0];
                $payloadBase64 = $tokenArray[1];
                $signatureBase64 = $tokenArray[2];
            } catch(Exception $e) {
                throw new Exception("jwt malformed");
            }

            $signatureVerify = hash_hmac('SHA256', "$headerBase64.$payloadBase64", $secret, true);
            $signatureVerifyBase64 = $this->base64url_encode($signatureVerify);

            if($signatureBase64 !== $signatureVerifyBase64) {
                throw new Exception("invalid signature");
            }

            $headerJSON = $this->base64url_decode($headerBase64);
            $header = json_decode($headerJSON, true);

            $payloadJSON = $this->base64url_decode($payloadBase64);
            $payload = json_decode($payloadJSON, true);

            if(isset($payload['nbf']) && $payload['nbf'] > time()) {
                throw new Exception("jwt not active");
            }

            if(isset($payload['exp']) && $payload['exp'] < time()) {
                throw new Exception("jwt expired");
            }

            return [
                'header' => $header,
                'payload' => $payload
            ];
        }

        public function decode($token) {
            try {
                $tokenArray = explode('.', $token);
                $headerBase64 = $tokenArray[0];
                $payloadBase64 = $tokenArray[1];
            } catch(Exception $e) {
                throw new Exception("jwt malformed");
            }

            $headerJSON = $this->base64url_decode($headerBase64);
            $header = json_decode($headerJSON, true);

            $payloadJSON = $this->base64url_decode($payloadBase64);
            $payload = json_decode($payloadJSON, true);

            return [
                'header' => $header,
                'payload' => $payload
            ];
        }
    }
