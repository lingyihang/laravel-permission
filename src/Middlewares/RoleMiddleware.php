<?php

namespace Yihang\Permission\Middlewares;

use Closure;
use Illuminate\Support\Facades\Auth;
use Yihang\Permission\Exceptions\UnauthorizedException;

class RoleMiddleware
{
    public function handle($request, Closure $next, $role, $guard = null)
    {
        $authGuard = Auth::guard($guard);

        if ($authGuard->guest()) {
            throw UnauthorizedException::notLoggedIn();
        }

        $roles = is_array($role)
            ? $role
            : explode('|', $role);

        if (! $authGuard->user()->hasAnyRole($guard,$authGuard->user()->company_id??0,$roles)) {
            throw UnauthorizedException::forRoles($roles);
        }

        return $next($request);
    }
}
