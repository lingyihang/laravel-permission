<?php

namespace Yihang\Permission\Contracts;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;

interface Permission
{
    /**
     * A permission can be applied to roles.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function roles(): BelongsToMany;

    /**
     * Find a permission by its name.
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     *
     * @throws \Yihang\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return Permission
     */
    public static function findByName(string $name, $guardName, int $companyId): self;

    /**
     * Find a permission by its id.
     *
     * @param int $id
     * @param string|null $guardName
     * @param int $companyId
     * @throws \Yihang\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return Permission
     */
    public static function findById(int $id, $guardName, int $companyId): self;

    /**
     * Find or Create a permission by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     * @return Permission
     */
    public static function findOrCreate(string $name, $guardName, int $companyId): self;
}
