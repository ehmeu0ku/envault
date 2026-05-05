# envault

> A local secret manager that encrypts `.env` files using age encryption for safe repo storage.

---

## Installation

```bash
go install github.com/yourusername/envault@latest
```

Or build from source:

```bash
git clone https://github.com/yourusername/envault.git && cd envault && go build -o envault .
```

---

## Usage

**Encrypt a `.env` file before committing:**

```bash
envault encrypt .env --output .env.age
```

**Decrypt when you need the secrets locally:**

```bash
envault decrypt .env.age --output .env
```

**Generate a new age key pair:**

```bash
envault keygen --output key.txt
```

Add `.env` to your `.gitignore` and safely commit `.env.age` to your repository.

```gitignore
# .gitignore
.env
key.txt
```

**Example workflow:**

```bash
# First time setup
envault keygen --output ~/.config/envault/key.txt

# Encrypt secrets before pushing
envault encrypt .env --output .env.age

# Teammate decrypts after pulling
envault decrypt .env.age --output .env
```

---

## License

[MIT](LICENSE)