<?php

namespace Yihang\Permission\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Collection;
use Yihang\Permission\Contracts\Permission;
use Yihang\Permission\Exceptions\GuardDoesNotMatch;
use Yihang\Permission\Exceptions\PermissionDoesNotExist;
use Yihang\Permission\Exceptions\WildcardPermissionInvalidArgument;
use Yihang\Permission\Guard;
use Yihang\Permission\PermissionRegistrar;
use Yihang\Permission\WildcardPermission;

trait HasPermissions
{
    /** @var string */
    private $permissionClass;

    public static function bootHasPermissions()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->permissions()->detach();
        });
    }

    public function getPermissionClass()
    {
        if (! isset($this->permissionClass)) {
            $this->permissionClass = app(PermissionRegistrar::class)->getPermissionClass();
        }

        return $this->permissionClass;
    }

    /**
     * A model may have multiple direct permissions.
     */
    public function permissions(): BelongsToMany
    {
        return $this->morphToMany(
            config('permission.models.permission'),
            'model',
            config('permission.table_names.model_has_permissions'),
            config('permission.column_names.model_morph_key'),
            'permission_id'
        );
    }

    /**
     * Scope the model query to certain permissions only.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     * @param int $companyId
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopePermission(Builder $query, $permissions, int $companyId): Builder
    {
        $permissions = $this->convertToPermissionModels($permissions, $companyId);

        $rolesWithPermissions = array_unique(array_reduce($permissions, function ($result, $permission) {
            return array_merge($result, $permission->roles->all());
        }, []));

        return $query->where(function (Builder $query) use ($permissions, $rolesWithPermissions) {
            $query->whereHas('permissions', function (Builder $subQuery) use ($permissions) {
                $subQuery->whereIn(config('permission.table_names.permissions').'.id', \array_column($permissions, 'id'));
            });
            if (count($rolesWithPermissions) > 0) {
                $query->orWhereHas('roles', function (Builder $subQuery) use ($rolesWithPermissions) {
                    $subQuery->whereIn(config('permission.table_names.roles').'.id', \array_column($rolesWithPermissions, 'id'));
                });
            }
        });
    }

    /**
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     * @param int $companyId
     * @return array
     * @throws \Yihang\Permission\Exceptions\PermissionDoesNotExist
     */
    protected function convertToPermissionModels($permissions, int $companyId): array
    {
        if ($permissions instanceof Collection) {
            $permissions = $permissions->all();
        }

        $permissions = is_array($permissions) ? $permissions : [$permissions];

        return array_map(function ($permission)use($companyId) {
            if ($permission instanceof Permission) {
                return $permission;
            }
            $method = is_string($permission) ? 'findByName' : 'findById';

            return $this->getPermissionClass()->{$method}($permission, $this->getDefaultGuardName(), $companyId);
        }, $permissions);
    }

    /**
     * Determine if the model may perform the given permission.
     *
     * @param string|int|\Yihang\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     * @param int $companyId
     * @return bool
     * @throws PermissionDoesNotExist
     */
    public function hasPermissionTo($permission, $guardName = null, int $companyId = 0): bool
    {
        if (config('permission.enable_wildcard_permission', false)) {
            return $this->hasWildcardPermission($permission, $guardName, $companyId);
        }

        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName(
                $permission,
                $guardName ?? $this->getDefaultGuardName(),
                $companyId
            );
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById(
                $permission,
                $guardName ?? $this->getDefaultGuardName(),
                $companyId
            );
        }

        if (!$permission instanceof Permission) {
            throw new PermissionDoesNotExist();
        }

        return $this->hasDirectPermission($permission) || $this->hasPermissionViaRole($permission);
    }

    /**
     * Validates a wildcard permission against all permissions of a user.
     *
     * @param string|int|\Yihang\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     * @param int $companyId
     * @return bool
     */
    protected function hasWildcardPermission($permission, $guardName = null, int $companyId = 0): bool
    {
        $guardName = $guardName ?? $this->getDefaultGuardName();

        if (is_int($permission)) {
            $permission = $this->getPermissionClass()->findById($permission, $guardName, $companyId);
        }

        if ($permission instanceof Permission) {
            $permission = $permission->name;
        }

        if (! is_string($permission)) {
            throw WildcardPermissionInvalidArgument::create();
        }

        foreach ($this->getAllPermissions() as $userPermission) {
            if ($guardName !== $userPermission->guard_name) {
                continue;
            }

            $userPermission = new WildcardPermission($userPermission->name);

            if ($userPermission->implies($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * An alias to hasPermissionTo(), but avoids throwing an exception.
     *
     * @param string|int|\Yihang\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     * @param int $companyId
     * @return bool
     */
    public function checkPermissionTo($permission, $guardName = null, int $companyId = 0): bool
    {
        try {
            return $this->hasPermissionTo($permission, $guardName, $companyId);
        } catch (PermissionDoesNotExist $e) {
            return false;
        }
    }

    /**
     * Determine if the model has any of the given permissions.
     *
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection ...$permissions
     *
     * @return bool
     */
    public function hasAnyPermission($guardName = null, int $companyId = 0, ...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->checkPermissionTo($permission, $guardName, $companyId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the model has all of the given permissions.
     *
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection ...$permissions
     *
     * @return bool
     * @throws \Exception
     */
    public function hasAllPermissions(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (! $this->hasPermissionTo($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine if the model has, via roles, the given permission.
     *
     * @param \Yihang\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     * @param int $companyId
     * @return bool
     */
    protected function hasPermissionViaRole(Permission $permission, $guardName = null, int $companyId = 0): bool
    {
        return $this->hasRole($permission->roles, $guardName, $companyId);
    }

    /**
     * Determine if the model has the given permission.
     *
     * @param string|int|\Yihang\Permission\Contracts\Permission $permission
     * @param int $companyId
     * @return bool
     * @throws PermissionDoesNotExist
     */
    public function hasDirectPermission($permission, int $companyId = 0): bool
    {
        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName($permission, $this->getDefaultGuardName(), $companyId);
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById($permission, $this->getDefaultGuardName(), $companyId);
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist;
        }

        return $this->permissions->contains('id', $permission->id);
    }

    /**
     * Return all the permissions the model has via roles.
     */
    public function getPermissionsViaRoles(): Collection
    {
        return $this->loadMissing('roles', 'roles.permissions')
            ->roles->flatMap(function ($role) {
                return $role->permissions;
            })->sort()->values();
    }

    /**
     * Return all the permissions the model has, both directly and via roles.
     */
    public function getAllPermissions(): Collection
    {
        /** @var Collection $permissions */
        $permissions = $this->permissions;

        if ($this->roles) {
            $permissions = $permissions->merge($this->getPermissionsViaRoles());
        }

        return $permissions->sort()->values();
    }

    /**
     * Grant the given permission(s) to a role.
     *
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return $this
     */
    public function givePermissionTo(int $companyId = 0, ...$permissions)
    {
        $permissions = collect($permissions)
            ->flatten()
            ->map(function ($permission)use($companyId) {
                if (empty($permission)) {
                    return false;
                }

                return $this->getStoredPermission($permission, $companyId);
            })
            ->filter(function ($permission) {
                return $permission instanceof Permission;
            })
            ->each(function ($permission)use($companyId) {
                $this->ensureModelSharesGuard($permission, $companyId);
            })
            ->map->id
            ->all();

        $model = $this->getModel();

        if ($model->exists) {
            $this->permissions()->sync($permissions, false);
            $model->load('permissions');
        } else {
            $class = \get_class($model);

            $class::saved(
                function ($object) use ($permissions, $model) {
                    if ($model->getKey() != $object->getKey()) {
                        return;
                    }
                    $model->permissions()->sync($permissions, false);
                    $model->load('permissions');
                }
            );
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Remove all current permissions and set the given ones.
     * @param int $companyId
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return $this
     */
    public function syncPermissions(int $companyId = 0,...$permissions)
    {
        $this->permissions()->detach();

        return $this->givePermissionTo($companyId, $permissions);
    }

    /**
     * Revoke the given permission.
     *
     * @param \Yihang\Permission\Contracts\Permission|\Yihang\Permission\Contracts\Permission[]|string|string[] $permission
     * @param int $companyId
     * @return $this
     */
    public function revokePermissionTo($permission, int $companyId)
    {
        $this->permissions()->detach($this->getStoredPermission($permission, $companyId));

        $this->forgetCachedPermissions();

        $this->load('permissions');

        return $this;
    }

    public function getPermissionNames(): Collection
    {
        return $this->permissions->pluck('name');
    }

    /**
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     * @param int $companyId
     * @return \Yihang\Permission\Contracts\Permission|\Yihang\Permission\Contracts\Permission[]|\Illuminate\Support\Collection
     */
    protected function getStoredPermission($permissions, int $companyId)
    {
        $permissionClass = $this->getPermissionClass();

        if (is_numeric($permissions)) {
            return $permissionClass->findById($permissions, $this->getDefaultGuardName(), $companyId);
        }

        if (is_string($permissions)) {
            return $permissionClass->findByName($permissions, $this->getDefaultGuardName(), $companyId);
        }

        if (is_array($permissions)) {
            return $permissionClass->whereIn('name', $permissions)->whereIn('guard_name', $this->getGuardNames())->where('company_id', $companyId)->get();
        }

        return $permissions;
    }

    /**
     * @param \Yihang\Permission\Contracts\Permission|\Yihang\Permission\Contracts\Role $roleOrPermission
     * @param int $companyId
     * @throws \Yihang\Permission\Exceptions\GuardDoesNotMatch
     */
    protected function ensureModelSharesGuard($roleOrPermission, int $companyId)
    {
        if (! $this->getGuardNames()->contains($roleOrPermission->guard_name)) {
            throw GuardDoesNotMatch::create($roleOrPermission->guard_name, $this->getGuardNames(), $companyId);
        }
    }

    protected function getGuardNames(): Collection
    {
        return Guard::getNames($this);
    }

    protected function getDefaultGuardName(): string
    {
        return Guard::getDefaultName($this);
    }

    /**
     * Forget the cached permissions.
     */
    public function forgetCachedPermissions()
    {
        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }

    /**
     * Check if the model has All of the requested Direct permissions.
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection ...$permissions
     * @return bool
     */
    public function hasAllDirectPermissions(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (!$this->hasDirectPermission($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the model has Any of the requested Direct permissions.
     * @param string|int|array|\Yihang\Permission\Contracts\Permission|\Illuminate\Support\Collection ...$permissions
     * @return bool
     */
    public function hasAnyDirectPermission(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->hasDirectPermission($permission)) {
                return true;
            }
        }

        return false;
    }
}
