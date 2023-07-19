<?php

namespace Yihang\Permission\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Yihang\Permission\Contracts\Role as RoleContract;
use Yihang\Permission\Exceptions\GuardDoesNotMatch;
use Yihang\Permission\Exceptions\RoleAlreadyExists;
use Yihang\Permission\Exceptions\RoleDoesNotExist;
use Yihang\Permission\Guard;
use Yihang\Permission\Traits\HasPermissions;
use Yihang\Permission\Traits\RefreshesPermissionCache;

class Role extends Model implements RoleContract
{
    use HasPermissions;
    use RefreshesPermissionCache;

    protected $guarded = ['id'];

    public function __construct(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? config('auth.defaults.guard');
        $attributes['company_id'] = $attributes['company_id']??0;
        parent::__construct($attributes);
    }

    public function getTable()
    {
        return config('permission.table_names.roles', parent::getTable());
    }

    public static function create(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? Guard::getDefaultName(static::class);
        $attributes['company_id'] = $attributes['company_id']??0;
        if (static::where('name', $attributes['name'])->where('guard_name', $attributes['guard_name'])->where('company_id',$attributes['company_id'])->first()) {
            throw RoleAlreadyExists::create($attributes['name'], $attributes['guard_name'], $attributes['company_id']);
        }

        return static::query()->create($attributes);
    }

    /**
     * A role may be given various permissions.
     */
    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(
            config('permission.models.permission'),
            config('permission.table_names.role_has_permissions'),
            'role_id',
            'permission_id'
        );
    }

    /**
     * A role belongs to some users of the model associated with its guard.
     */
    public function users(): BelongsToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->attributes['guard_name']),
            'model',
            config('permission.table_names.model_has_roles'),
            'role_id',
            config('permission.column_names.model_morph_key')
        );
    }

    /**
     * Find a role by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     * @return \Yihang\Permission\Contracts\Role|\Yihang\Permission\Models\Role
     *
     * @throws \Yihang\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByName(string $name, $guardName = null, int $companyId = 0): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::where('name', $name)->where('guard_name', $guardName)->where('company_id', $companyId)->first();

        if (! $role) {
            throw RoleDoesNotExist::named($name, $companyId);
        }

        return $role;
    }

    public static function findById(int $id, $guardName = null, int $companyId = 0): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::where('id', $id)->where('guard_name', $guardName)->where('company_id', $companyId)->first();

        if (! $role) {
            throw RoleDoesNotExist::withId($id, $companyId);
        }

        return $role;
    }

    /**
     * Find or create role by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     * @return \Illuminate\Database\Eloquent\Builder|Model|RoleContract
     */
    public static function findOrCreate(string $name, $guardName = null, int $companyId = 0): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::where('name', $name)->where('guard_name', $guardName)->where('company_id', $companyId)->first();

        if (! $role) {
            return static::query()->create(['name' => $name, 'guard_name' => $guardName, 'company_id'=>$companyId]);
        }

        return $role;
    }

    /**
     * Determine if the user may perform the given permission.
     *
     *
     * @param string|\Yihang\Permission\Contracts\Permission $permission
     * @param int $companyId
     * @return bool
     *
     * @throws \Yihang\Permission\Exceptions\GuardDoesNotMatch
     */
    public function hasPermissionTo($permission, int $companyId): bool
    {
        if (config('permission.enable_wildcard_permission', false)) {
            return $this->hasWildcardPermission($permission, $this->getDefaultGuardName());
        }

        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName($permission, $this->getDefaultGuardName(), $companyId);
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById($permission, $this->getDefaultGuardName(), $companyId);
        }

        if (!$this->getGuardNames()->contains($permission->guard_name)) {
            throw GuardDoesNotMatch::create($permission->guard_name, $this->getGuardNames(), $companyId);
        }

        return $this->permissions->contains('id', $permission->id);
    }
}
