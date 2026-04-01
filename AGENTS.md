Auth Bundle – Agent Notes

Core principles:
- No AbstractController usage
- Constructor injection only
- No controller.service_arguments
- Use prependExtensionConfig for cross-bundle config (ux_icons, etc)
- Twig components are the public API

Auth responsibilities:
- OAuth login
- User creation
- Provider linking (future)

Onboarding responsibilities (NOT here):
- profile enrichment
- organization membership

Icons:
- Use semantic keys (add_user, login, etc)
- Aliases registered via prependExtension

Common pitfalls:
- Do NOT mutate IconRegistry directly
- Do NOT use @!base.html.twig
- Do NOT use method injection in controllers
