<?php

namespace Yihang\Permission\Exceptions;

use InvalidArgumentException;

class PermissionAlreadyExists extends InvalidArgumentException
{
    public static function create(string $permissionName, string $guardName, int $companyId)
    {
        return new static("A `{$permissionName}` permission already exists for guard `{$guardName}` and company `{$companyId}`.");
    }
}
