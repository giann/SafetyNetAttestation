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
    public static function rootCertificate(): string
    {
        $certificate = self::findInLocalCache();

        if (!self::validateCertFile($certificate)) {
            $certificate = null;
        }

        if (!empty($certificate)) {
            return $certificate;
        }

        try {
            $certificate = self::findInLocalBundle();
        } catch (RootCertificateError $exception) {
            $certificate = self::getCertificateFromGoogle();
        }

        return $certificate;
    }

    /**
     * @return string|null
     * @throws RootCertificateError
     */
    private static function findInLocalBundle(): ?string
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
                self::saveToLocalCache($rawCert);
                return $rawCert;
            }
        }

        throw new RootCertificateError('Local certificate bundle is unavailable');
    }

    private static function saveToLocalCache(string $rawCert): void
    {
        @file_put_contents(self::getCertCacheFile(), $rawCert);
    }

    private static function getCertCacheFile(): string
    {
        return sys_get_temp_dir() . '/' . self::SAVE_CACHE_FILE_NAME;
    }

    private static function findInLocalCache(): ?string
    {
        if (!is_file(self::getCertCacheFile())) {
            return null;
        }

        return @file_get_contents(self::getCertCacheFile());
    }

    /**
     * @return string|null
     * @throws RootCertificateError
     */
    private static function getCertificateFromGoogle(): ?string
    {
        $crtFile = @file_get_contents(self::CRT_FILE_URL);
        if (empty($crtFile)) {
            throw new RootCertificateError("Can't load root cert from google");
        }
        return chunk_split(base64_encode($crtFile), 64, PHP_EOL);
    }

    private static function validateCertFile(?string $certificate): bool
    {
        if (empty($certificate)) {
            return false;
        }

        $cert = new X509();
        $cert->loadX509($certificate);
        return $cert->validateDate();
    }
}
