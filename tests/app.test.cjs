const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { test } = require('node:test')
const vm = require('node:vm')
const path = require('node:path')

function createComponent() {
  let factory
  const requests = []
  const context = vm.createContext({
    document: { addEventListener: (_, listener) => listener() },
    Alpine: { data: (_, value) => { factory = value } },
    TextEncoder,
    fetch: async (_, options) => {
      requests.push(JSON.parse(options.body))
      return { ok: true, status: 200, blob: async () => ({}) }
    },
    URL: { createObjectURL: () => 'blob:test' },
    requestAnimationFrame: callback => callback(),
  })
  vm.runInContext(readFileSync(path.join(__dirname, '../web/static/app.js'), 'utf8'), context)
  return {
    component: { ...factory(), $refs: { download: { checkVisibility: () => true, focus() {} } } },
    requests,
  }
}

test('valid Unicode text reaches the server unchanged', async () => {
  for (const text of ['a'.repeat(1000), '😀'.repeat(550), '😀'.repeat(582)]) {
    const { component, requests } = createComponent()
    component.text = text
    await component.generate()
    assert.equal(requests[0].text, text)
    assert.equal(component.error, '')
  }
})

test('over-limit text is preserved and rejected before submitting', async () => {
  for (const text of ['a'.repeat(1001), '😀'.repeat(583)]) {
    const { component, requests } = createComponent()
    component.text = text
    await component.generate()
    assert.equal(requests.length, 0)
    assert.equal(component.text, text)
    assert.match(component.error, /too long/i)
    assert.equal(component.loading, false)
  }
})

test('IME confirmation and Shift+Enter do not submit', () => {
  for (const properties of [{ isComposing: true }, { keyCode: 229 }, { shiftKey: true }]) {
    const { component } = createComponent()
    component.generate = () => assert.fail('must not submit')
    component.submitOnEnter({
      shiftKey: false,
      isComposing: false,
      keyCode: 13,
      preventDefault: () => assert.fail('must not cancel composition or newline'),
      ...properties,
    })
  }
})

test('ordinary Enter submits once', () => {
  const { component } = createComponent()
  let generated = 0
  let prevented = 0
  component.generate = () => { generated++ }
  component.submitOnEnter({ shiftKey: false, isComposing: false, keyCode: 13, preventDefault: () => { prevented++ } })
  assert.equal(generated, 1)
  assert.equal(prevented, 1)
})
