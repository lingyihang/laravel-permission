<?php

namespace Yihang\Permission\Exceptions;

use InvalidArgumentException;

class RoleAlreadyExists extends InvalidArgumentException
{
    public static function create(string $roleName, string $guardName, int $companyId)
    {
        return new static("A role `{$roleName}` already exists for guard `{$guardName}`.");
    }
}
