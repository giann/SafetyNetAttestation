<?php

namespace SafetyNet;

use SafetyNet\Config\Config;
use SafetyNet\Statement\Statement;
use SafetyNet\Verifier\OfflineVerifier;
use SafetyNet\Verifier\OnlineVerifier;
use SafetyNet\Verifier\Verifier;
use SafetyNet\Verifier\VerifierType;

class Attestation
{
    private Config $config;
    private Verifier $verifier;

    public function __construct(Config $attestationConfig)
    {
        $this->config = $attestationConfig;
        $this->verifier = $this->buildVerifier($this->config->getVerifierType());
    }

    /**
     * @param Nonce $nonce
     * @param Statement $attestationStatement
     * @return bool
     */
    public function verify(Nonce $nonce, Statement $attestationStatement): bool
    {
        return $this->verifier->verify($nonce, $attestationStatement);
    }

    private function buildVerifier(VerifierType $verifierType): ?Verifier
    {
        if (VerifierType::isONLINE($verifierType)) {
            return new OnlineVerifier($this->config);
        }

        if (VerifierType::isOFFLINE($verifierType)) {
            return new OfflineVerifier($this->config);
        }

        return null;
    }
}