<?php

namespace Survos\AuthBundle\Command;

use Doctrine\ORM\EntityManagerInterface;
use Survos\AuthBundle\Event\UserCreatedEvent;
use Symfony\Component\Cache\CacheItem;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Contracts\Cache\CacheInterface;

#[AsCommand('survos:user:create', 'create a new user with a password')]
final class UserCreateCommand
{
    public function __construct(
        private UserPasswordHasherInterface $passwordEncoder,
        private UserProviderInterface $userProvider,
        private EventDispatcherInterface $eventDispatcher,
        private EntityManagerInterface $entityManager,
        private CacheInterface $cache,
    ) {
    }

    private function hashPassword(string $plainTextPassword, $user): string
    {
        return $this->cache->get($plainTextPassword, fn(CacheItem $item) => $this->passwordEncoder->hashPassword($user, $plainTextPassword));
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument('email address of account')] string $email,
        #[Argument('Plain text password')] ?string $password = null,
        #[Option('comma-delimited list of roles')] ?string $roles = null,
        #[Option('Update password')] bool $changePassword = false,
        #[Option('username (defaults to email)')] ?string $username = null,
        #[Option('user class')] string $userclass = 'App\\Entity\\User',
        #[Option('extra string passed to event dispatcher')] ?string $extra = null,
        #[Option('Change password/roles if account exists')] bool $force = false,
    ): int {
        $action = 'no-action';
        $username ??= $email;

        try {
            $user = $this->userProvider->loadUserByIdentifier($username);
            if (!$changePassword && !$roles) {
                $io->warning("$email already exists, use --change-password to overwrite the existing password");
            } else {
                $action = 'updated';
            }
        } catch (UserNotFoundException) {
            $action = 'created';
            $user = new $userclass();

            if ($username !== $email) {
                $user->setUsername($email);
            } else {
                $user->setEmail($email);
            }
            $this->entityManager->persist($user);
        }

        if ($roles) {
            $user->setRoles(explode(',', $roles));
        }

        if ($password) {
            $user->setPassword($this->hashPassword($password, $user));
        }

        $this->eventDispatcher->dispatch(new UserCreatedEvent($user, $extra));

        $this->entityManager->flush();

        if ($io->isVerbose()) {
            $table = new Table($io);
            $table
                ->setHeaders(['Field', 'Value'])
                ->setRows([
                    ['email', $user->getEmail()],
                    ['roles', join(',', $user->getRoles())],
                ]);
            $table->render();
        }

        $io->success("User $email $action");
        return Command::SUCCESS;
    }
}
