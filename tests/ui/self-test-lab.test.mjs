import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"
import { webUIFile } from "./web-ui-source.mjs"

const main = webUIFile("main.tsx")
const system = webUIFile("workspaces/system/SystemWorkspace.tsx")
const ui = webUIFile("workspaces/system/TestLabPanel.tsx")
const unit = await readFile(new URL("../../packaging/systemd/shakerproxy-testlab.service", import.meta.url), "utf8")
const packageBuilder = await readFile(new URL("../../packaging/build-deb.sh", import.meta.url), "utf8")
const daemon = await readFile(new URL("../../host/testlab/cmd/shakerproxy-testlabd/main.go", import.meta.url), "utf8")

test("Virtual Test Lab is a React panel mounted only inside the signed-in System workspace", () => {
  assert.match(main, /styles\/self-test-lab\.css/)
  assert.match(system, /<TestLabPanel \/>/)
  assert.doesNotMatch(ui, /document\.getElementById\("root"\)|firstElementChild/)
  assert.match(ui, /Virtual Test Lab/)
  assert.match(ui, /Quick/)
  assert.match(ui, /DNS/)
  assert.match(ui, /TLS/)
  assert.match(ui, /Full/)
  assert.match(ui, /withPassword\("create the virtual test clients"/)
  assert.doesNotMatch(ui, /type="password"/)
  assert.match(ui, /\/api\/v1\/self-test\/status/)
  assert.match(ui, /\/api\/v1\/self-test\/run/)
  assert.match(ui, /\/api\/v1\/self-test\/cleanup/)
})

test("UI preserves PASS FAIL SKIP evidence semantics", () => {
  assert.match(ui, /PASS means the named virtual runtime check actually succeeded/)
  assert.match(ui, /SKIP means ShakerProxy deliberately did not claim product proof/)
  assert.match(ui, /Physical Android, iOS, Wi-Fi, and Smart TV behavior still requires real-device testing/)
  assert.doesNotMatch(ui, /all capabilities verified/i)
})

test("self-test polling is bounded and uses the shared session", () => {
  assert.match(ui, /refreshInFlight/)
  assert.match(ui, /usePolling\([\s\S]{0,80}?, 10_000/)
  assert.match(ui, /from "\.\.\/\.\.\/api"/)
  assert.doesNotMatch(ui, /MutationObserver|window\.fetch|bearerToken/)
})

test("test-lab host service remains narrow and package-owned", () => {
  assert.match(packageBuilder, /shakerproxy-testlabd/)
  assert.match(packageBuilder, /shakerproxy-testlab\.service/)
  assert.match(unit, /CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN/)
  assert.match(unit, /RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK/)
  assert.match(unit, /ReadWritePaths=\/var\/lib\/shakerproxy\/control-api \/run\/lock\/shakerproxy -\/run\/netns/)
  assert.doesNotMatch(unit, /docker\.sock/)
  assert.doesNotMatch(unit, /0\.0\.0\.0/)
})

test("virtual network mutations participate in appliance configuration lock", () => {
  assert.match(daemon, /configlock\.Manager\{\}\)\.Acquire/)
  assert.match(daemon, /Category:\s+configlock\.CategoryNetwork/)
  assert.match(daemon, /Actor:\s+"shakerproxy-testlabd"/)
  assert.match(daemon, /net\.ipv4\.ip_forward=/)
  assert.match(daemon, /cleanupLab\(cleanupCtx\)/)
})
