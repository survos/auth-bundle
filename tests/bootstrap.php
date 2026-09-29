<?php

declare(strict_types=1);

$autoload = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoload)) {
    $autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
}
$loader = require $autoload;
$loader->addPsr4('Survos\\AuthBundle\\', dirname(__DIR__) . '/src');
