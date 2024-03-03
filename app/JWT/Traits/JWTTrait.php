<?php

declare(strict_types=1);

namespace App\JWT\Traits;

use App\JWT\Exceptions\Base64UrlDecodeException;
use App\JWT\Exceptions\Base64UrlEncodeException;
use App\JWT\Exceptions\HeaderEncodeException;
use App\JWT\Exceptions\ParseException;
use App\JWT\Exceptions\PayloadEncodeException;
use App\JWT\Exceptions\SignatureEncodeException;
use Carbon\Carbon;
use DateTimeZone;
use Throwable;

trait JWTTrait
{
    /**
     * @throws Base64UrlEncodeException
     */
    private function base64UrlEncode(string $string): string
    {
        try {
            $string = trim($string);
            if ($string === '') {
                return '';
            }
            $string = base64_encode($string);
            $string = strtr($string, '+/', '-_');
            return rtrim($string, '=');
        } catch (Throwable $throwable) {
            throw new Base64UrlEncodeException($throwable->getMessage(), (int)$throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws Base64UrlDecodeException
     */
    public function base64UrlDecode(string $string, bool $strict = false): string
    {
        try {
            $string = trim($string);
            if ($string === '') {
                return '';
            }
            $string = str_pad($string, strlen($string) % 4, '=', STR_PAD_RIGHT);
            $string = strtr($string, '-_', '+/');
            return base64_decode($string, $strict);
        } catch (Throwable $throwable) {
            throw new Base64UrlDecodeException($throwable->getMessage(), (int)$throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws HeaderEncodeException
     */
    private function headerEncode(): string
    {
        try {
            $header = [
                'alg' => 'HS512',
                'typ' => 'JWT',
            ];
            return $this->base64UrlEncode(
                json_encode($header, JSON_OBJECT_AS_ARRAY | JSON_BIGINT_AS_STRING | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            );
        } catch (Throwable $throwable) {
            throw new HeaderEncodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws PayloadEncodeException
     */
    private function payloadEncode(int $subject, Carbon $expirationTime, array $customClaims): string
    {
        try {
            if ($subject < 1) {
                throw new PayloadEncodeException(
                    sprintf("Subject (%s) Can't Be Zero Or Negative", $subject)
                );
            }

            $timezone = new DateTimeZone('UTC');

            $iat = Carbon::now($timezone);

            $exp = $expirationTime->setTimezone($timezone);
            if ($exp < $iat) {
                throw new PayloadEncodeException(
                    sprintf("Expiration Time (%s UTC) Can't Be Earlier Than Current Time (%s UTC)", $exp->format('Y/m/d H:i:s'), $iat->format('Y/m/d H:i:s'))
                );
            }

            $payload = array_merge($customClaims, [
                'sub' => $subject,
                'iat' => $iat->getTimestamp(),
                'exp' => $exp->getTimestamp(),
            ]);

            return $this->base64UrlEncode(
                json_encode($payload, JSON_OBJECT_AS_ARRAY | JSON_BIGINT_AS_STRING | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            );
        } catch (PayloadEncodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new PayloadEncodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws SignatureEncodeException
     */
    private function signatureEncode(string $headerEncoded, string $payloadEncoded): string
    {
        try {
            $signatureKey = trim(config('jwt.signature_key', ''));
            if ($signatureKey === '') {
                throw new SignatureEncodeException('JWT Signature Key Is Empty');
            }
            $signature = hash_hmac('sha512', $headerEncoded . "." . $payloadEncoded, $signatureKey, true);
            return $this->base64UrlEncode($signature);
        } catch (SignatureEncodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new SignatureEncodeException($throwable->getMessage(), $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws Base64UrlDecodeException
     * @throws ParseException
    */
    private function payloadDecode(string $payload): array
    {
        $payload = $this->base64UrlDecode($payload);
        $payloadDecoded = json_decode($payload, true, 512, JSON_OBJECT_AS_ARRAY | JSON_BIGINT_AS_STRING | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if (array_key_exists('sub', $payloadDecoded) === false) {
            throw new ParseException('JWT Payload Is Invalid : Subject Is Not Found');
        }
        $subject = (int)($payloadDecoded['sub'] ?? 0);
        if ($subject < 1) {
            throw new ParseException('JWT Payload Is Invalid : Subject Is Invalid');
        }
        unset($payloadDecoded['sub']);
        $payloadDecoded['subject'] = $subject;

        $timezone = new DateTimeZone('UTC');

        if (array_key_exists('iat', $payloadDecoded) === false) {
            throw new ParseException('JWT Payload Is Invalid : Issued At Is Not Found');
        }
        $issuedAt = (int)($payloadDecoded['iat'] ?? 0);
        if ($issuedAt < 1) {
            throw new ParseException('JWT Payload Is Invalid : Issued At Is Invalid');
        }
        $issuedAt = Carbon::createFromTimestamp($issuedAt, $timezone);
        if ($issuedAt > Carbon::now($timezone)) {
            throw new ParseException('JWT Payload Is Invalid : Issued At Is Invalid');
        }
        unset($payloadDecoded['iat']);
        $payloadDecoded['issued_at'] = $issuedAt;

        if (array_key_exists('exp', $payloadDecoded) === false) {
            throw new ParseException('JWT Payload Is Invalid : Expiration Time Is Not Found');
        }
        $expirationTime = (int)($payloadDecoded['exp'] ?? 0);
        if ($expirationTime < 1) {
            throw new ParseException('JWT Payload Is Invalid : Expiration Time Is Invalid');
        }
        $expirationTime = Carbon::createFromTimestamp($expirationTime, $timezone);
        if ($expirationTime < $issuedAt) {
            throw new ParseException('JWT Payload Is Invalid : Expiration Time Is Invalid');
        }
        unset($payloadDecoded['exp']);
        $payloadDecoded['expiration_time'] = $expirationTime;

        return $payloadDecoded;
    }


}
