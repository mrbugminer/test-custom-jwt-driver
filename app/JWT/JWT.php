<?php

declare(strict_types=1);

namespace App\JWT;

use App\JWT\Exceptions\GenerateException;
use App\JWT\Exceptions\HeaderEncodeException;
use App\JWT\Exceptions\ParseException;
use App\JWT\Exceptions\PayloadEncodeException;
use App\JWT\Exceptions\SignatureEncodeException;
use App\JWT\Traits\JWTTrait;
use Carbon\Carbon;
use Throwable;

final class JWT
{
    use JWTTrait;

    /**
     * @throws HeaderEncodeException
     * @throws PayloadEncodeException
     * @throws SignatureEncodeException
     * @throws GenerateException
     */
    public function generate(int $subject, Carbon $expirationTime, array $customClaims): string
    {
        try {
            $headerEncoded = $this->headerEncode();

            $payloadEncoded = $this->payloadEncode($subject, $expirationTime, $customClaims);

            $signatureEncoded = $this->signatureEncode($headerEncoded, $payloadEncoded);

            return $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
        } catch (HeaderEncodeException|PayloadEncodeException|SignatureEncodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new GenerateException($throwable->getMessage(), (int)$throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws ParseException
     * @throws HeaderEncodeException
     * @throws SignatureEncodeException
     */
    public function parse(string $jwt): array
    {
        try {
            $jwt = trim($jwt);
            if ($jwt === '') {
                throw new ParseException('JWT Is Empty');
            }

            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                throw new ParseException('JWT Structure Is Invalid');
            }

            if ($parts[0] !== $this->headerEncode()) {
                throw new ParseException('JWT Header Is Invalid');
            }

            $payloadDecoded = $this->payloadDecode($parts[1]);

            if ($parts[2] !== $this->signatureEncode($parts[0], $parts[1])) {
                throw new ParseException('JWT Signature Is Invalid');
            }

            return $payloadDecoded;
        } catch (ParseException|HeaderEncodeException|SignatureEncodeException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new ParseException($throwable->getMessage(), (int)$throwable->getCode(), $throwable);
        }
    }
}
