<?php

namespace Yihang\Permission\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Collection;
use Yihang\Permission\Contracts\Role;
use Yihang\Permission\PermissionRegistrar;

trait HasRoles
{
    use HasPermissions;

    /** @var string */
    private $roleClass;

    public static function bootHasRoles()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->roles()->detach();
        });
    }

    public function getRoleClass()
    {
        if (! isset($this->roleClass)) {
            $this->roleClass = app(PermissionRegistrar::class)->getRoleClass();
        }

        return $this->roleClass;
    }

    /**
     * A model may have multiple roles.
     */
    public function roles(): BelongsToMany
    {
        return $this->morphToMany(
            config('permission.models.role'),
            'model',
            config('permission.table_names.model_has_roles'),
            config('permission.column_names.model_morph_key'),
            'role_id'
        );
    }

    /**
     * Scope the model query to certain roles only.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|int|array|\Yihang\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     * @param string $guard
     * @param int $companyId
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeRole(Builder $query, $roles, $guard = null, int $companyId = 0): Builder
    {
        if ($roles instanceof Collection) {
            $roles = $roles->all();
        }

        if (! is_array($roles)) {
            $roles = [$roles];
        }

        $roles = array_map(function ($role) use ($guard,$companyId) {
            if ($role instanceof Role) {
                return $role;
            }

            $method = is_numeric($role) ? 'findById' : 'findByName';

            return $this->getRoleClass()->{$method}($role, $guard ?: $this->getDefaultGuardName(), $companyId);
        }, $roles);

        return $query->whereHas('roles', function (Builder $subQuery) use ($roles) {
            $subQuery->whereIn(config('permission.table_names.roles').'.id', \array_column($roles, 'id'));
        });
    }

    /**
     * Assign the given role to the model.
     * @param int $companyId
     * @param array|string|int|\Yihang\Permission\Contracts\Role|\Illuminate\Support\Collection ...$roles
     *
     * @return $this
     */
    public function assignRole(int $companyId, ...$roles)
    {
        $roles = collect($roles)
            ->flatten()
            ->map(function ($role)use($companyId) {
                if (empty($role)) {
                    return false;
                }

                return $this->getStoredRole($role, $companyId);
            })
            ->filter(function ($role) {
                return $role instanceof Role;
            })
            ->each(function ($role)use($companyId) {
                $this->ensureModelSharesGuard($role, $companyId);
            })
            ->map->id
            ->all();

        $model = $this->getModel();

        if ($model->exists) {
            $this->roles()->sync($roles, false);
            $model->load('roles');
        } else {
            $class = \get_class($model);

            $class::saved(
                function ($object) use ($roles, $model) {
                    if ($model->getKey() != $object->getKey()) {
                        return;
                    }
                    $model->roles()->sync($roles, false);
                    $model->load('roles');
                }
            );
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke the given role from the model.
     *
     * @param string|int|\Yihang\Permission\Contracts\Role $role
     */
    public function removeRole($role, int $companyId)
    {
        $this->roles()->detach($this->getStoredRole($role, $companyId));

        $this->load('roles');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Remove all current roles and set the given ones.
     *
     * @param  array|\Yihang\Permission\Contracts\Role|\Illuminate\Support\Collection|string|int  ...$roles
     *
     * @return $this
     */
    public function syncRoles(int $companyId,...$roles)
    {
        $this->roles()->detach();

        return $this->assignRole($companyId, $roles);
    }

    /**
     * Determine if the model has (one of) the given role(s).
     *
     * @param string|int|array|\Yihang\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     * @param string|null $guard
     * @param int $companyId
     * @return bool
     */
    public function hasRole($roles, string $guard = null, int $companyId = 0): bool
    {
        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $guard
                ? $this->roles->where('guard_name', $guard)->where('company_id', $companyId)->contains('name', $roles)
                : $this->roles->where('company_id', $companyId)->contains('name', $roles);
        }

        if (is_int($roles)) {
            return $guard
                ? $this->roles->where('guard_name', $guard)->where('company_id', $companyId)->contains('id', $roles)
                : $this->roles->where('company_id', $companyId)->contains('id', $roles);
        }

        if ($roles instanceof Role) {
            return $this->roles->contains('id', $roles->id);
        }

        if (is_array($roles)) {
            foreach ($roles as $role) {
                if ($this->hasRole($role, $guard, $companyId)) {
                    return true;
                }
            }

            return false;
        }

        return $roles->intersect($guard ? $this->roles->where('guard_name', $guard)->where('company_id', $companyId) : $this->roles->where('company_id', $companyId))->isNotEmpty();
    }

    /**
     * Determine if the model has any of the given role(s).
     *
     * Alias to hasRole() but without Guard controls
     * @param string $guard
     * @param int $companyId
     * @param string|int|array|\Yihang\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasAnyRole(string $guard = null, int $companyId = 0,...$roles): bool
    {
        return $this->hasRole($roles, $guard, $companyId);
    }

    /**
     * Determine if the model has all of the given role(s).
     *
     * @param  string|array|\Yihang\Permission\Contracts\Role|\Illuminate\Support\Collection  $roles
     * @param  string|null  $guard
     * @param int $companyId
     * @return bool
     */
    public function hasAllRoles($roles, string $guard = null, int $companyId = 0): bool
    {
        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $guard
                ? $this->roles->where('guard_name', $guard)->where('company_id', $companyId)->contains('name', $roles)
                : $this->roles->where('company_id', $companyId)->contains('name', $roles);
        }

        if ($roles instanceof Role) {
            return $this->roles->contains('id', $roles->id);
        }

        $roles = collect()->make($roles)->map(function ($role) {
            return $role instanceof Role ? $role->name : $role;
        });

        return $roles->intersect(
            $guard
                ? $this->roles->where('guard_name', $guard)->where('company_id', $companyId)->pluck('name')
                : $this->getRoleNames($companyId)
        ) == $roles;
    }

    /**
     * Determine if the model has exactly all of the given role(s).
     *
     * @param  string|array|\Yihang\Permission\Contracts\Role|\Illuminate\Support\Collection  $roles
     * @param  string|null  $guard
     * @param int $companyId
     * @return bool
     */
    public function hasExactRoles($roles, string $guard = null, int $companyId = 0): bool
    {
        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            $roles = [$roles];
        }

        if ($roles instanceof Role) {
            $roles = [$roles->name];
        }

        $roles = collect()->make($roles)->map(function ($role) {
            return $role instanceof Role ? $role->name : $role;
        });

        return $this->roles->where('company_id', $companyId)->count() == $roles->where('company_id', $companyId)->count() && $this->hasAllRoles($roles, $guard, $companyId);
    }

    /**
     * Return all permissions directly coupled to the model.
     */
    public function getDirectPermissions(): Collection
    {
        return $this->permissions;
    }

    public function getRoleNames(int $companyId): Collection
    {
        return $this->roles->where('company_id', $companyId)->pluck('name');
    }

    protected function getStoredRole($role, int $companyId): Role
    {
        $roleClass = $this->getRoleClass();

        if (is_numeric($role)) {
            return $roleClass->findById($role, $this->getDefaultGuardName(), $companyId);
        }

        if (is_string($role)) {
            return $roleClass->findByName($role, $this->getDefaultGuardName(), $companyId);
        }

        return $role;
    }

    protected function convertPipeToArray(string $pipeString)
    {
        $pipeString = trim($pipeString);

        if (strlen($pipeString) <= 2) {
            return $pipeString;
        }

        $quoteCharacter = substr($pipeString, 0, 1);
        $endCharacter = substr($quoteCharacter, -1, 1);

        if ($quoteCharacter !== $endCharacter) {
            return explode('|', $pipeString);
        }

        if (! in_array($quoteCharacter, ["'", '"'])) {
            return explode('|', $pipeString);
        }

        return explode('|', trim($pipeString, $quoteCharacter));
    }
}
