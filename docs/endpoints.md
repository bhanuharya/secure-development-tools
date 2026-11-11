# Endpoints: the route inventory and its access-control checks

Pattern rules see one file. Whether a route is protected is often decided
elsewhere: a middleware registered once, a router group, a security
configuration. `sdt endpoints` lists every route with its effective protection.

## The command

```bash
sdt endpoints [DIR] [-o FILE] [--format json|csv|table] [--findings FILE]
```

`DIR` defaults to `.`. Without `-o` the default format is `table`; with `-o` it is
`json`. `--format` wins over both. `--findings FILE` also writes the convention
findings as a JSON array in the finding schema `sdt scan` uses.

```console
$ sdt endpoints testdata/endpoints/convention
SERVICE  METHOD  PATH                   PROTECTION     HANDLER           FILE:LINE
.        POST    /api/accounts          authenticated  createAccount     main.go:14
.        DELETE  /api/admin/sessions    role           revokeSession     main.go:19
.        GET     /api/admin/users       public         listUsers         main.go:23
...
```

Exit `0` on success, also with findings; `2` on bad input; `3` when the engine
or a rule directory fails.

When the scan profile includes the `endpoints` scanner, `sdt scan` runs the same
inventory, writes `endpoints.json` next to `findings.json`, and adds them to the run.

## Reading the inventory

`routes` is sorted by service, path and method. Each route has its service
directory, framework, method, full path, handler, `file:line`, protection,
roles, evidence (`file:line what decided it`) and confidence. Path parameters
become `{name}`.

| Protection | Meaning |
|---|---|
| `public` | No gate was found on the route, its groups or the engine. |
| `authenticated` | A gate middleware, decorator, guard or security rule requires a logged-in user. |
| `role` | The gate also names a role or authority; `roles` lists it. |
| `denied` | A Spring Security rule denies every request. |
| `unknown` | The decision may live in a file this resolver cannot see. Never reported as a finding. |

## How routes are resolved

**Go: gin, echo, fiber, chi, net/http.** Routes come from the router calls and
from `Group(prefix, middleware...)`, `Use(middleware)` and the engine's own
`Use`. Prefixes nest. Gin, chi and net/http put the handler last; echo and fiber
put middleware after it. A route is protected when any middleware on its chain
matches the gate list. A middleware that names a role makes it `role`.

**Spring MVC and WebFlux.** The class `@RequestMapping` is the prefix; the method
annotation supplies the verb and path. `@PreAuthorize`, `@Secured` and
`@RolesAllowed` decide first, and a method gate wins over a class gate. Without
one, the service's Spring Security configuration decides: matchers are read in
source order, an optional `HttpMethod` filter applies, and the first match wins.
`anyRequest()` is the fallback. A service without a configuration, or a route
that no matcher covers, is not guessed: the first is `unknown`, the second is
`public` with low confidence.

**Express and NestJS.** Express routes are `router.METHOD(path, ...middleware,
handler)`. `router.use(middleware)` applies to routes registered after it in the
same file. `app.use(prefix, ...middleware, router)` adds both when the router is
created in that file; a router mounted elsewhere gives `unknown`. In NestJS,
`@Controller(prefix)` and `@Get`/`@Post`/... supply the route. `@UseGuards` on the
class or method gives `authenticated`, `@Roles` gives `role`, and `@Public`
gives `public`. No guard is `unknown` when the service registers a global guard
(`APP_GUARD` or `useGlobalGuards`), otherwise `public`.

**Flask and FastAPI.** Routes come from `@app.route`, `@app.get/post/...` and
`@router.get/...`, including `methods=[...]`. `APIRouter(prefix=,
dependencies=...)`, `include_router` and `register_blueprint` are followed in the
same file. Gate decorators (`login_required`, `jwt_required`,
`roles_required("admin")`) and FastAPI `Depends`/`Security` parameters and router
dependencies are matched by name.

## The three findings

A route produces at most one finding; the first rule that applies wins. The
first rule counts only state-changing routes (POST, PUT, PATCH, DELETE, ANY);
the other two count every method. Unknown routes are counted, never reported.

**`scp.endpoints.unprotected-among-protected`** (warning, CWE-306, CWE-862).
The service has at least `minRoutes` state-changing routes, at least `majority`
of the known-protection routes are `authenticated` or `role`, and this route is
`public`.

```text
POST /api/funds/transfer is public while 9 of 10 state-changing routes in this
service require authentication (most often "main.go:9 middleware AuthMiddleware
on group /api"). Anyone can call it; add the same gate or move the route under
the protected group.
```

**`scp.endpoints.sensitive-route-public`** (error, CWE-306, CWE-284). Any route
whose path matches the sensitive list is `public`.

```text
GET /api/admin/users is public, but its path matches the sensitive pattern
"/admin". Anyone who can reach the service can use an administrative or
money-moving endpoint; require authentication and a role that matches the
operation.
```

**`scp.endpoints.sensitive-route-without-role`** (warning, CWE-285). A sensitive
route is `authenticated` while the same service has at least one `role` route.

```text
PUT /api/admin/roles/{id} only requires a logged-in user, but this service also
checks roles (e.g. "main.go:18 middleware RequireRole(\"admin\") on group
/admin"). Any authenticated user can reach this sensitive endpoint; add the role
gate the rest of the service uses.
```

## Configuration

Defaults are in code. Overrides go under `endpoints` in `.secure-dev.yaml`:

```yaml
endpoints:
  authGates: ["AuthMiddleware", "verifyJwt"]   # extra gate names
  publicPaths: ["^/api/v1/rates$"]             # extra public-by-design paths
  sensitivePaths: ["/payouts"]                 # extra sensitive paths
  minRoutes: 5
  majority: 0.7
```

`publicPaths` and `sensitivePaths` are regular expressions added to the built-in
lists. The defaults cover login, health, docs, webhooks and callbacks on the
public side, and administration, internal, roles, transfer, withdrawal,
approval and password reset on the sensitive side. `authGates` is read and
validated but not yet applied: the resolvers still use the built-in gate list.

## Limits

- **Same file only.** A router, group or blueprint created or mounted in another
  file gives `unknown`, with a sentence in `unresolved`. A flow through several
  files is not followed.
- **Names, not data flow.** A gate with a name the list does not know can be
  missed; a middleware whose name looks like a gate can be taken for one.
- **Build and test trees are skipped:** `node_modules`, `vendor`, `dist`,
  `build`, test directories, `*_test.go`, `*.spec.*` and `*.test.*`.
- **Frameworks not covered:** Kotlin and Ktor, Django, Rails and ASP.NET. The
  scanner needs Opengrep and the rules under `rules/endpoint-facts/`.
- **The Word report uses the default sensitive list.** It reads `endpoints.json`,
  which does not record paths added in configuration.
