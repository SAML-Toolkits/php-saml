<?php

/**
 * Attribute Policy helper functions
 *
 */

class OneLogin_Saml2_Settings_AttributePolicyHelpers
{
    static function restrictValuesTo($validValues) {
        return function($values) use ($validValues) {
            $newValues = array();
            foreach ($values as $value) {
                if (in_array($value, $validValues, true)) {
                    array_push($newValues, $value);
                }
            }
            return $newValues;
        };
    };

    static function requireScope($scope) {
        $scope = str_replace('.', '\.', $scope);
        return function ($values) use ($scope) {
            $newValues = preg_grep('/^[^@]+@' . $scope . '$/', $values);
            return $newValues;
        };
    }
}
