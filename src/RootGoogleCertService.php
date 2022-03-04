<?php

namespace SafetyNet;

use phpseclib\File\X509;
use SafetyNet\Statement\Exception\RootCertificateError;

class RootGoogleCertService
{
    public const SAVE_CACHE_FILE_NAME = 'GoogleGlobalSign.pem';
    public const CRT_FILE_URL = 'https://pki.goog/repo/certs/gsr4.der';

    /**
     * @return string
     * @throws RootCertificateError
     */
    public function rootCertificate(): string
    {
        $certificate = $this->findInLocalCache();

        if (!$this->validateCertFile($certificate)) {
            $certificate = null;
        }

        if (!empty($certificate)) {
            return $certificate;
        }

        try {
            $certificate = $this->findInLocalBundle();
        } catch (RootCertificateError $exception) {
            $certificate = $this->getCertificateFromGoogle();
        }

        return $certificate;
    }

    /**
     * @return string|null
     * @throws RootCertificateError
     */
    private function findInLocalBundle(): ?string
    {
        $localCerts = openssl_get_cert_locations();

        if (
            empty($localCerts['ini_cafile'])
            || !($caCerts = file_get_contents($localCerts['ini_cafile']))
        ) {
            throw new RootCertificateError('Local certificate bundle is unavailable');
        }

        $rawCerts = explode("-----END CERTIFICATE-----", str_replace("-----BEGIN CERTIFICATE-----", "", $caCerts));
        foreach ($rawCerts as $rawCert) {
            $rawCert = trim($rawCert);
            if (empty($rawCert)) {
                continue;
            }
            $x509 = new X509();
            $x509->loadX509($rawCert);
            $CN = $x509->getDNProp('CN');
            if (!empty($CN) && $CN[0] === 'GlobalSign') {
                $this->saveToLocalCache($rawCert);
                return $rawCert;
            }
        }

        throw new RootCertificateError('Local certificate bundle is unavailable');
    }

    private function saveToLocalCache(string $rawCert): void
    {
        @file_put_contents($this->getCertCacheFile(), $rawCert);
    }

    private function getCertCacheFile(): string
    {
        return sys_get_temp_dir() . '/' . self::SAVE_CACHE_FILE_NAME;
    }

    private function findInLocalCache(): ?string
    {
        if (!is_file($this->getCertCacheFile())) {
            return null;
        }

        return @file_get_contents($this->getCertCacheFile());
    }

    /**
     * @return string|null
     * @throws RootCertificateError
     */
    private function getCertificateFromGoogle(): ?string
    {
        // For some reason, using symfony/http-client does not work
        $cert = file_get_contents(
            self::CRT_FILE_URL,
            false,
            stream_context_create([
                'http' => [
                    'proxy' => preg_replace('/^http/', 'tcp', $_SERVER['HTTPS_PROXY']),
                    'request_fulluri' => true,
                ]
            ])
        );

        if ($cert === false) {
            throw new RootCertificateError("Can't load root cert from google");
        }

        return chunk_split(base64_encode($cert), 64, PHP_EOL);
    }

    private function validateCertFile(?string $certificate): bool
    {
        if (empty($certificate)) {
            return false;
        }

        $cert = new X509();
        $cert->loadX509($certificate);
        return $cert->validateDate();
    }
}
