<?php

namespace Yihang\Permission\Exceptions;

use InvalidArgumentException;

class PermissionDoesNotExist extends InvalidArgumentException
{
    public static function create(string $permissionName, string $guardName = '', int $companyId = 0)
    {
        return new static("There is no permission named `{$permissionName}` for guard `{$guardName}` and company `{$companyId}`.");
    }

    public static function withId(int $permissionId, string $guardName = '', int $companyId = 0)
    {
        return new static("There is no [permission] with id `{$permissionId}` for guard `{$guardName}` and company `{$companyId}`.");
    }
}
