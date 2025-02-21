<?php

namespace SafetyNet\Statement;

use DomainException;
use Firebase\JWT\JWT;
use SafetyNet\RootGoogleCertService;
use SafetyNet\Statement\Exception\InvalidJWSFormat;

class Statement
{
    private string $rawStatement;
    private string $rawHeader;
    private string $rawBody;
    private string $rawSignature;
    private StatementHeader $header;
    private StatementBody $body;
    private string $signature;
    private RootGoogleCertService $rootGoogleCertService;

    public function __construct(RootGoogleCertService $rootGoogleCertService, string $statement)
    {
        $this->rootGoogleCertService = $rootGoogleCertService;
        $this->rawStatement = $statement;
        $this->extractFromJWS($this->rawStatement);
    }

    public function getRawHeaders(): string
    {
        return $this->rawHeader;
    }

    public function getRawBody(): string
    {
        return $this->rawBody;
    }

    public function getHeader(): StatementHeader
    {
        return $this->header;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getBody(): StatementBody
    {
        return $this->body;
    }

    /**
     * @param string $rawStatement
     * @throws InvalidJWSFormat
     */
    private function extractFromJWS(string $rawStatement): void
    {
        $tokens = explode('.', $this->rawStatement);
        if (count($tokens) !== 3) {
            throw new InvalidJWSFormat('Wrong number of segments of JWS in statement');
        }

        [$headB64, $bodyB64, $cryptoB64] = $tokens;

        $header = self::jsonDecode(self::urlSafeB64Decode($headB64));
        if (empty($header)) {
            throw new InvalidJWSFormat('Invalid header encoding');
        }

        $body = self::jsonDecode(self::urlSafeB64Decode($bodyB64));
        if (empty($body)) {
            throw new InvalidJWSFormat('Invalid claims encoding');
        }

        $this->rawBody = $bodyB64;
        $this->rawHeader = $headB64;
        $this->rawSignature = $cryptoB64;
        $this->header = new StatementHeader($this->rootGoogleCertService, $header);
        $this->body = new StatementBody($body);
        $this->signature = self::urlSafeB64Decode($cryptoB64);
    }

    /**
     * @param string $json
     * @return array
     * @throws InvalidJWSFormat
     */
    private static function jsonDecode(string $json): array
    {
        try {
            return (array) JWT::jsonDecode($json);
        } catch (DomainException $e) {
            throw new InvalidJWSFormat($e->getMessage());
        }
    }

    private static function urlSafeB64Decode(string $input): string
    {
        return JWT::urlsafeB64Decode($input);
    }

    public function toString(): string
    {
        return $this->rawStatement;
    }
}
