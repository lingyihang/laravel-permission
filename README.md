# Associate users with permissions and roles

## fork spatie/laravel-permission


## desc

with many company

## What It Does
This package allows you to manage user permissions and roles in a database.

Once installed you can do stuff like this:

```php
// Adding permissions to a user
$user->givePermissionTo('edit articles');

// Adding permissions via a role
$user->assignRole('writer');

$role->givePermissionTo('edit articles');
```


```php
$user->can('edit articles');
```


### Testing

``` bash
composer test
```


## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
