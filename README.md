# otp
`otp` is a one time password manager in Rust, that can handle both Time (TOTP) and Event (EOTP) one time passwords.

## TODOS
- [ ] Add customization regarding import/export location
- [ ] Add customization regarding default datastore location
- [ ] Check cross-platform compatibility
- [ ] Add better user-facing error handling

## Example: Creating a TOTP
Secrets are base32 strings. 

```
  ~ otp new github -u nathan-yan
  Secret: **************
  Wrote to github (nathan-yan). Cleaning up...
```

## Example: Creating an EOTP
```
  ~ otp new some_website --event
  Secret: **************
  Wrote to some_website. Cleaning up...
```

## Example: Displaying OTPs
```
  ~ otp show

    a: github (nathan-yan)
       123 456 · 25

    b: some_website
       234 567 · 25
```

```
  ~ otp show github

    a: github (nathan-yan)
       123 456 · 25
```

## Copying a OTP
To copy a OTP, type the letter that addresses the OTP, and press the `spacebar`. 

As an example, if you type `otp show` and you get
```
    a: github (nathan-yan)
       123 456 · 25

    b: event_eotp
       --- ---

    c: some_website
       234 567 · 25
```

And you'd like to copy the OTP for "github", simply type the letter `a` and press `spacebar`. The code "123456" will automatically be copied to your clipboard.

## Incrementing an EOTP
To increment an EOTP, type the letter that addresses the EOTP and press `enter`.

As an example, if you type `otp show` and you get 
```
    a: github (nathan-yan)
       123 456 · 25

    b: event_eotp
       --- ---

    c: some_website
       234 567 · 25
```

You would type the letter `b`. Letters `a` and `c` correspond to "github" and "some_website" respectively, both of which are TOTPs. Once you type `b`, you'll notice that the EOTP is selected:

```
    a: github (nathan-yan)
       123 456 · 25

  │ b: event
  │    --- ---

    c: some_website
       234 567 · 25
```

Now you can press `enter` to increment the EOTP. The EOTP will automatically start a cooldown timer, preventing you from accidentally incrementing many times in a short window.

```
    a: github (nathan-yan)
       123 456 · 25

  │ b: event
  │    678 901 × 5

    c: some_website
       234 567 · 25
```
