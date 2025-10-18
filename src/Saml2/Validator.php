<?php

namespace OneLogin\Saml2;

use DOMDocument;

/**
 * Class Validador
 *
 * This class provides methods to validate SAML messages.
 */
class Validator
{

    /**
     * Security settings.
     *
     * @var array
     */
    public static array $security;

    /**
     * Checks the Destination attribute of a SAML message.
     *
     * @param DOMDocument $document The SAML message as a DOMDocument.
     * @param string $currentURL The current URL where the message was received.
     * @param string $method The method being validated (e.g., "AuthnRequest", "Response").
     *
     * @throws ValidationError If the Destination is invalid.
     */
    public static function checkDestination(DOMDocument $document, string $currentURL, string $method)
    {
        $destination = $document->documentElement->getAttribute('Destination');
        $destination = trim($destination);
        if (empty($destination)) {
            if (!self::$security['relaxDestinationValidation']) {
                throw new ValidationError(
                    "The $method has an empty Destination value",
                    ValidationError::EMPTY_DESTINATION
                );
            }
        } else {
            $urlComparisonLength = self::$security['destinationStrictlyMatches'] ? strlen($destination) : strlen($currentURL);
            if (strncmp($destination, $currentURL, $urlComparisonLength) !== 0) {
                $currentURLNoRouted = Utils::getSelfURLNoQuery();
                $urlComparisonLength = self::$security['destinationStrictlyMatches'] ? strlen($destination) : strlen($currentURLNoRouted);
                if (strncmp($destination, $currentURLNoRouted, $urlComparisonLength) !== 0) {
                    throw new ValidationError(
                        "The $method was received at $currentURL instead of $destination",
                        ValidationError::WRONG_DESTINATION
                    );
                }
            }
        }
    }

}
