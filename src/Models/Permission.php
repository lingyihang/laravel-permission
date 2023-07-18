<?php

namespace Yihang\Permission\Models;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Yihang\Permission\Contracts\Permission as PermissionContract;
use Yihang\Permission\Exceptions\PermissionAlreadyExists;
use Yihang\Permission\Exceptions\PermissionDoesNotExist;
use Yihang\Permission\Guard;
use Yihang\Permission\PermissionRegistrar;
use Yihang\Permission\Traits\HasRoles;
use Yihang\Permission\Traits\RefreshesPermissionCache;

class Permission extends Model implements PermissionContract
{
    use HasRoles;
    use RefreshesPermissionCache;

    protected $guarded = ['id'];

    public function __construct(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? config('auth.defaults.guard');

        parent::__construct($attributes);
    }

    public function getTable()
    {
        return config('permission.table_names.permissions', parent::getTable());
    }

    public static function create(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? Guard::getDefaultName(static::class);
        $attributes['company_id'] = $attributes['company_id']??0;
        $permission = static::getPermission(['name' => $attributes['name'], 'guard_name' => $attributes['guard_name'], 'company_id'=>$attributes['company_id']]);

        if ($permission) {
            throw PermissionAlreadyExists::create($attributes['name'], $attributes['guard_name'], $attributes['company_id']);
        }

        return static::query()->create($attributes);
    }

    /**
     * A permission can be applied to roles.
     */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(
            config('permission.models.role'),
            config('permission.table_names.role_has_permissions'),
            'permission_id',
            'role_id'
        );
    }

    /**
     * A permission belongs to some users of the model associated with its guard.
     */
    public function users(): BelongsToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->attributes['guard_name']),
            'model',
            config('permission.table_names.model_has_permissions'),
            'permission_id',
            config('permission.column_names.model_morph_key')
        );
    }

    /**
     * Find a permission by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     * @throws \Yihang\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Yihang\Permission\Contracts\Permission
     */
    public static function findByName(string $name, $guardName = null, int $companyId = 0): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);
        $permission = static::getPermission(['name' => $name, 'guard_name' => $guardName, 'company_id'=>$companyId]);
        if (! $permission) {
            throw PermissionDoesNotExist::create($name, $guardName, $companyId);
        }

        return $permission;
    }

    /**
     * Find a permission by its id (and optionally guardName).
     *
     * @param int $id
     * @param string|null $guardName
     * @param int $companyId
     * @throws \Yihang\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Yihang\Permission\Contracts\Permission
     */
    public static function findById(int $id, $guardName = null, int $companyId = 0): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);
        $permission = static::getPermission(['id' => $id, 'guard_name' => $guardName, 'company_id'=>$companyId]);

        if (! $permission) {
            throw PermissionDoesNotExist::withId($id, $guardName, $companyId);
        }

        return $permission;
    }

    /**
     * Find or create permission by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     * @param int $companyId
     * @return \Illuminate\Database\Eloquent\Builder|Model|PermissionContract
     */
    public static function findOrCreate(string $name, $guardName = null, int $companyId = 0): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);
        $permission = static::getPermission(['name' => $name, 'guard_name' => $guardName, 'company_id'=>$companyId]);

        if (! $permission) {
            return static::query()->create(['name' => $name, 'guard_name' => $guardName, 'company_id'=>$companyId]);
        }

        return $permission;
    }

    /**
     * Get the current cached permissions.
     *
     * @param array $params
     * @param bool $onlyOne
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    protected static function getPermissions(array $params = [], bool $onlyOne = false): Collection
    {
        return app(PermissionRegistrar::class)
            ->setPermissionClass(static::class)
            ->getPermissions($params, $onlyOne);
    }

    /**
     * Get the current cached first permission.
     *
     * @param array $params
     *
     * @return \Yihang\Permission\Contracts\Permission
     */
    protected static function getPermission(array $params = []): ?PermissionContract
    {
        return static::getPermissions($params, true)->first();
    }
}
