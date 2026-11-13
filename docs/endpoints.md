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
The default `full` and `pr` profiles include it. In a pull request scan the inventory
covers the whole repository, and the baseline comparison keeps only the findings the pull
request adds, so a new public sensitive route is reported on the pull request itself.

## Reading the inventory

`routes` is sorted by service, path and method. Each route has its service
directory, framework, method, full path, handler, `file:line`, protection,
roles, evidence (`file:line what decided it`) and confidence. Path parameters
become `{name}`.

`path` is the path inside the application, which is what Spring Security matchers,
the path lists and finding fingerprints use. When a Spring service's base
configuration (`application.yml`, `.yaml` or `.properties`, outside test and build
trees) adds a prefix the code does not show, the route also has `externalPath`, the
path as served: `server.servlet.context-path` (or Boot 1's `server.context-path`)
plus `spring.mvc.servlet.path` for Spring MVC, `spring.webflux.base-path` for
WebFlux. `${NAME:default}` uses the default; `${NAME}` without one leaves
`externalPath` out with a sentence in `unresolved`, as does a profile file
(`application-prod.yml`) that sets a different prefix. Finding messages and the
Word report show `externalPath` when there is one.

| Protection | Meaning |
|---|---|
| `public` | No gate was found on the route, its groups or the engine. |
| `authenticated` | A gate middleware, decorator, guard or security rule requires a logged-in user. |
| `role` | The gate also names a role or authority; `roles` lists it. |
| `denied` | A Spring Security rule denies every request. |
| `unknown` | The decision may live in a file this resolver cannot see. Never reported as a finding. |

## Changes between scans

The Word report's Endpoints section ends with **Changes since previous scan** when the
previous report's state (`report-state.json`, kept by the Jenkins integration) is available.
The state records each route's service, method, path, protection and `file:line`; no code.
The section counts new routes, routes with weaker protection (for example `role` to
`authenticated`, or anything to `public`) and removed routes, and lists the new public or
unknown routes and the weaker ones. A route that became `unknown` is only counted: the tool
lost certainty, which often comes from a newer SDT version rather than from the code.

## How routes are resolved

**Go: gin, echo, fiber, chi, net/http.** Routes come from the router calls and
from `Group(prefix, middleware...)`, `Use(middleware)` and the engine's own
`Use`. Prefixes nest. Gin, chi and net/http put the handler last; echo and fiber
put middleware after it. A route is protected when any middleware on its chain
matches the gate list. A middleware that names a role makes it `role`.

A function that receives the router (`func Register(grp fiber.Router)`) is
resolved from its calls: in the same file, from the other files of its package,
and from packages that import it (`orders.Register(api)`; the import path is
mapped to a directory through `go.mod`). A method (`h.Routes(r)`) is matched in its
package, or anywhere when no other method with a router parameter has that name. A
function called with routers under different prefixes registers its routes once
per caller; callers that reach the same path with different middleware leave that
path `unknown`, and so does a function no call reaches. A middleware held in a
variable (`mw := auth.Jwt(key)` then `grp.Use(mw)`) is read as the call that built
it. A value built from a group (`checked := NewRoleRouter(group, perms)`) inherits
the group, and its constructor counts as a middleware on every route registered
through it.

A router kept in a struct field (`s.Router = app` in a method, or
`&Server{Router: app}`) is resolved from that field's assignments in its package,
read at the assignment. Routes registered on the field (`s.Router.Get(...)`) use
it, and so do routes registered through the type's own `Get`/`Post`/... methods
when those forward to the field (`func (s *Server) Post(p string, h ...fiber.Handler)
{ s.Router.Post(p, h...) }`). Middleware that a function registers on a router
passed to it (`setupMiddlewares(app)`) counts for routes registered after that
call.

**Spring MVC and WebFlux.** The class `@RequestMapping` is the prefix; the method
annotation supplies the verb and path. `@PreAuthorize`, `@Secured` and
`@RolesAllowed` decide first, and a method gate wins over a class gate. Without
one, the service's Spring Security configuration decides: matchers are read in
source order, an optional `HttpMethod` filter applies, and the first match wins.
`anyRequest()` is the fallback. A service without a configuration, or a route
that no matcher covers, is not guessed: the first is `unknown`, the second is
`public` with low confidence.

**Express and NestJS.** Express routes are `router.METHOD(path, ...middleware,
handler)`. `router.use(middleware)` applies to routes registered after it on that
router. `app.use(prefix, ...middleware, router)` adds the prefix and middleware to
the router it mounts, also when the router comes from another file: a router
imported with `require` or `import` (`app.use('/api', routes)`), a member of an
imported module (`routes.userRouter`), `require('./users')` written in the call, or
a factory call (`router.use('/users', createUserRouter(deps))`) whose function
declares the router and returns it. Relative imports are followed, with the
extensions and `index` files Node and TypeScript try; package names and path
aliases (`@/routes`) are not. A router with a gate of its own
(`router.use(requireLogin)`) keeps it when its mount cannot be followed: the route
is `authenticated` with `medium` confidence and its path lacks the mount prefix,
which `unresolved` says. A router no mount reaches, or one mounted twice with
different prefixes or middleware, gives `unknown`. An application or router passed
into a function (`module.exports = (app) => { app.get(...) }`) is resolved from the
calls that pass it: `require('./users')(app)`, an imported function
(`registerUsers(api)`), a member of an imported module (`routes.register(app)`) or a
function in the same file. Callers that pass routers with different prefixes or
middleware leave the routes `unknown`. In NestJS,
`@Controller(prefix)` and `@Get`/`@Post`/... supply the route. `@UseGuards` on the
class or method gives `authenticated`, `@Roles` gives `role`, and `@Public`
gives `public`. No guard is `unknown` when the service registers a global guard
(`APP_GUARD` or `useGlobalGuards`), otherwise `public`.

**Flask and FastAPI.** Routes come from `@app.route`, `@app.get/post/...` and
`@router.get/...`, including `methods=[...]`. `APIRouter(prefix=,
dependencies=...)`, `include_router` and `register_blueprint` are followed across
modules through imports: `from app.routers.users import router as users_router`,
`from .routers import admin` used as `admin.router`, and `import app.api as api`.
Absolute imports are looked up from every folder between the importing file and
the repository root. Gate decorators (`login_required`, `jwt_required`,
`roles_required("admin")`) and FastAPI `Depends`/`Security` parameters and router
dependencies are matched by name.

## The three findings

A route produces at most one finding: the most severe applicable rule wins
(`sensitive-route-public`, then `unprotected-among-protected`, then
`sensitive-route-without-role`). Rule 1 counts only state-changing routes (POST,
PUT, PATCH, DELETE, ANY) and leaves out public-by-design paths; the other two
count every method. A public-by-design path is skipped by rule 1 only: a
sensitive name such as `/auth/reset-password` is still an error when public.
Unknown routes are counted, never reported.

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
A self-service route with no `{param}` segment whose only sensitive match is
`change-password`, `update-password` or `update-email` is not reported: any
logged-in user is the right audience for changing their own password or email.
`/users/{id}/change-password` still is, because it acts on another account.

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
lists. The defaults cover login, registration, health, docs, webhooks and
callbacks on the public side, and administration, internal, roles, transfer,
withdrawal, approval and password reset on the sensitive side. `authGates`
lists literal middleware or dependency names added to the built-in gate list,
so a gate unknown to the defaults (`checkCaller`) protects Go, JavaScript and
Python routes too.

### Authentication upstream (API gateway, mesh)

A service behind an API gateway that validates every request may leave its own
routes open. Declare it in the repository, in `.secure-dev/endpoints.yaml`:

```yaml
upstreamAuth:
  - service: "."             # service directory; omit (or "*") for every service
    paths: ["/api/**"]       # Ant patterns on the in-app path; omit for every route
    by: API gateway (JWT)    # who authenticates; required, shown as evidence
```

The same list is accepted as `endpoints.upstreamAuth` in a scan configuration,
and both apply. A covered route keeps the protection the service itself enforces
(`public` stays `public`: inside the network it is reachable without the gateway)
and gains `upstreamAuth` plus an evidence line naming the declaration. The
convention findings judge it as `authenticated`: no "public" finding, but
"sensitive route accepts any authenticated user" still applies when the service
checks roles elsewhere. The Word report leaves such routes out of the public
list and says how many were declared. A declaration silences findings, so review
changes to this file like any other security configuration.

## Limits

- **Across files, with limits.** Go, Express, Flask and FastAPI follow routers
  across files as described above. A router no call, mount or include reaches
  gives `unknown`, with a sentence in `unresolved`. Not followed: a Go router
  returned by a function (`r := NewRouter()`), an Express router built by a class
  method, and Python imports through a path alias, `importlib`, or `import a.b`
  without `as`.
- **Names, not data flow.** A gate with a name the list does not know can be
  missed; add it under `endpoints.authGates`. A middleware whose name looks
  like a gate can be taken for one.
- **Build and test trees are skipped:** `node_modules`, `vendor`, `dist`,
  `build`, test directories, `*_test.go`, `*.spec.*` and `*.test.*`.
- **Frameworks not covered:** Kotlin and Ktor, Django, Rails and ASP.NET. The
  scanner needs Opengrep and the rules under `rules/endpoint-facts/`.
- **The Word report uses the default path lists.** It reads `endpoints.json`,
  which does not record paths added in configuration.
