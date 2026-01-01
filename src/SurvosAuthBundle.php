<?php

namespace Survos\AuthBundle;

use Survos\AuthBundle\Command\UserCreateCommand;
use Survos\AuthBundle\Controller\OAuthController;
use Survos\AuthBundle\Security\Authenticator;
use Survos\AuthBundle\Services\AuthService;
use Survos\AuthBundle\Twig\TwigExtension;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Survos\AuthBundle\Twig\Components\OAuth;
class SurvosAuthBundle extends AbstractBundle
{
    protected string $extensionAlias = 'survos_auth';

    /**
     * @param array<mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $serviceId = 'survos_auth.base_service';
        $container->services()->alias(AuthService::class, $serviceId);
        $builder->autowire($serviceId, AuthService::class)
            ->setArgument('$userClass', $config['user_class'])
            ->setArgument('$clientRegistry', new Reference('knpu.oauth2.registry'))
            ->setArgument('$logger', new Reference('logger', ContainerInterface::NULL_ON_INVALID_REFERENCE))
            ->setArgument('$config', $config)
//            ->setArgument('$entityManager', new Reference('doctrine.orm.entity_manager'))
//            ->setArgument('$registry', new Reference('doctrine'))
//            ->setArgument('$provider', new Reference('security.user_providers'))
            ->setPublic(true)
        ;

        // the social media login buttons
        foreach (
            [
                OAuth::class,
            ] as $componentClass
        ) {
            $builder->register($componentClass)
                ->setAutowired(true)
                ->setAutoconfigured(true);
        }

        $definition = $builder->autowire(Authenticator::class)
            ->setAutowired(true)
            ->setAutoconfigured(true)
            ->setArgument('$clientRegistry', new Reference('knpu.oauth2.registry'))
            ->setArgument('$entityManager', new Reference('doctrine.orm.entity_manager'))
            ->setArgument('$router', new Reference('router'))
            ->setArgument('$userClass', $config['user_class'])
            ->setArgument('$newUserRedirectRoute', $config['new_user_redirect_route'])
            ;



        $definition = $builder
            ->autowire('survos.auth_twig', TwigExtension::class)
            ->addTag('twig.extension');
        //        $definition->setArgument('$seed', $config['seed']);
        //        $definition->setArgument('$prefix', $config['function_prefix']);

        $builder->autowire(UserCreateCommand::class)
            ->setArgument('$passwordEncoder', new Reference('security.user_password_hasher'))
            ->setArgument('$userProvider', new Reference('security.user_providers'))
            ->setArgument('$eventDispatcher', new Reference('event_dispatcher'))
            ->setArgument('$entityManager', new Reference('doctrine.orm.entity_manager'))
            ->addTag('console.command')
        ;

        $definition = $builder->autowire(OAuthController::class)
            ->setArgument('$baseService', new Reference($serviceId))
            ->setArgument('$registry', new Reference('doctrine'))
            ->setArgument('$router', new Reference('router'))
            ->setArgument('$userClass', $config['user_class'])
            ->setArgument('$logger', new Reference('logger', ContainerInterface::NULL_ON_INVALID_REFERENCE))
//            ->setArgument('$entityManager', new Reference('doctrine.orm.entity_manager'))
//            ->setArgument('$userProvider', new Reference('doctrine.orm.security.user.provider'))
            ->setArgument('$clientRegistry', new Reference('knpu.oauth2.registry'))
            ->addTag('container.service_subscriber')
            ->addTag('controller.service_arguments')
            ->setPublic(true);

        if ($userProviderServiceId = $config['user_provider']) {
            $definition
                ->addMethodCall('setUserProvider', [new Reference($userProviderServiceId)])
            ;
        }
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        // since the configuration is short, we can add it here
        $definition->rootNode()
            ->children()
            ->scalarNode('new_user_redirect_route')->defaultValue('oauth_profile')->end()
            ->scalarNode('user_provider')->defaultValue(null)->end()
            ->scalarNode('user_class')->defaultValue("App\\Entity\\User")->end()
            ->end();
        ;
    }
}
