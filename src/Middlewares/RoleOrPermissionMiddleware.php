<?php

namespace Yihang\Permission\Middlewares;

use Closure;
use Illuminate\Support\Facades\Auth;
use Yihang\Permission\Exceptions\UnauthorizedException;

class RoleOrPermissionMiddleware
{
    public function handle($request, Closure $next, $roleOrPermission, $guard = null)
    {
        $authGuard = Auth::guard($guard);
        if ($authGuard->guest()) {
            throw UnauthorizedException::notLoggedIn();
        }

        $rolesOrPermissions = is_array($roleOrPermission)
            ? $roleOrPermission
            : explode('|', $roleOrPermission);

        if (! $authGuard->user()->hasAnyRole($guard,$authGuard->user()->company_id??0,$rolesOrPermissions) && ! $authGuard->user()->hasAnyPermission($guard,$authGuard->user()->company_id??0,$rolesOrPermissions)) {
            throw UnauthorizedException::forRolesOrPermissions($rolesOrPermissions);
        }

        return $next($request);
    }
}
