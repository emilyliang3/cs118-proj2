# Design choices
I chose to use the provided starter code so I did not make too many design choices, I just filled in the template. For writing to the buffer I chose to write directly for type and length fields (bit shifting to account for big endianness in the length field) and to use memcpy to write directly for the longer variable fields. For variable lengths like signatures I computed the signature first and stored it in a separate buffer so that I would know what length value to put and then copied the temp buffer values over.

# Problems and solutions
In hindsight I should not have done this project in the middle of the night because my problems were so stupid and I probably wasted several hours lol.
1) Key exchange request on client side- I was verifiying the server's nonce (instead of the client's nonce) with the server's signed client nonce. It took me 2 hours to finally realize this.
2) I did not call derive_secret() and my encrypt/decrypt were not working. It took another hour until I happened to hover over decrypt_cipher() and read the function description saying to call derive_secret().
3) I forgot a return statement in send data and it took me an embarassingly long time to realize that.