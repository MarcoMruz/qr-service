const GENERIC_ERROR = 'Something went wrong. Please try again.'
const OFFLINE_ERROR = 'Could not reach the server. Check your connection and try again.'
const EMPTY_ERROR = 'Paste a link or some text first.'
const TOO_LONG_ERROR = "That's too long for a QR code. Try a shorter link or text."
const MAX_TEXT_CHARS = 1000
const MAX_TEXT_BYTES = 2331

function textValidationError(text) {
  if (text === '') return EMPTY_ERROR
  if (Array.from(text).length > MAX_TEXT_CHARS || new TextEncoder().encode(text).length > MAX_TEXT_BYTES) return TOO_LONG_ERROR
  return ''
}

async function readErrorMessage(response) {
  try {
    const body = await response.json()
    return body.error || GENERIC_ERROR
  } catch {
    return GENERIC_ERROR
  }
}

// x-show reveals elements a frame later, and hidden elements can't take focus.
function focusWhenShown(element, framesLeft = 10) {
  requestAnimationFrame(() => {
    if (element.checkVisibility()) element.focus()
    else if (framesLeft > 0) focusWhenShown(element, framesLeft - 1)
  })
}

function requestQrCode(text) {
  return fetch('/api/qr', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
    credentials: 'same-origin',
  })
}

document.addEventListener('alpine:init', () => {
  Alpine.data('qrMaker', () => ({
    text: '',
    submittedText: '',
    imageUrl: '',
    error: '',
    loading: false,

    get showForm() { return this.imageUrl === '' },
    get showResult() { return this.imageUrl !== '' },
    get hasError() { return this.error !== '' },
    get submitLabel() { return this.loading ? 'Creating…' : 'Create QR code' },

    clearError() {
      this.error = ''
    },

    // Enter submits like a normal input; Shift+Enter still adds a line for plain text.
    submitOnEnter(event) {
      if (event.shiftKey || event.isComposing || event.keyCode === 229) return
      event.preventDefault()
      this.generate()
    },

    async generate() {
      if (this.loading) return
      const text = this.text.trim()
      this.error = textValidationError(text)
      if (this.error !== '') return

      this.loading = true
      this.error = ''
      try {
        const response = await requestQrCode(text)
        if (response.status === 401) {
          window.location.reload()
          return
        }
        if (!response.ok) {
          this.error = await readErrorMessage(response)
          return
        }
        this.imageUrl = URL.createObjectURL(await response.blob())
        this.submittedText = text
        focusWhenShown(this.$refs.download)
      } catch {
        this.error = OFFLINE_ERROR
      } finally {
        this.loading = false
      }
    },

    reset() {
      URL.revokeObjectURL(this.imageUrl)
      this.imageUrl = ''
      this.submittedText = ''
      this.text = ''
      this.error = ''
      focusWhenShown(this.$refs.input)
    },
  }))
})
