<?php

namespace Yihang\Permission\Exceptions;

use InvalidArgumentException;

class RoleDoesNotExist extends InvalidArgumentException
{
    public static function named(string $roleName, int $companyId)
    {
        return new static("There is no role named `{$roleName}` and company `{$companyId}`.");
    }

    public static function withId(int $roleId, int $companyId)
    {
        return new static("There is no role with id `{$roleId}` and company `{$companyId}`.");
    }
}
