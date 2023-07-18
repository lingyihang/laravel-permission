<?php

namespace Yihang\Permission\Contracts;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;

interface Role
{
    /**
     * A role may be given various permissions.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function permissions(): BelongsToMany;

    /**
     * Find a role by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     * @return \Yihang\Permission\Contracts\Role
     *
     * @throws \Yihang\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByName(string $name, $guardName, int $companyId): self;

    /**
     * Find a role by its id and guard name.
     *
     * @param int $id
     * @param string|null $guardName
     * @param int $companyId
     * @return \Yihang\Permission\Contracts\Role
     *
     * @throws \Yihang\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findById(int $id, $guardName, int $companyId): self;

    /**
     * Find or create a role by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     * @return \Yihang\Permission\Contracts\Role
     */
    public static function findOrCreate(string $name, $guardName, int $companyId): self;

    /**
     * Determine if the user may perform the given permission.
     *
     * @param string|\Yihang\Permission\Contracts\Permission $permission
     * @param int $companyId
     * @return bool
     */
    public function hasPermissionTo($permission, int $companyId): bool;
}
