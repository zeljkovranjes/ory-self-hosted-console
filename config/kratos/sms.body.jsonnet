// Kratos SMS courier HTTP-channel body template.
//
// Kratos renders this Jsonnet for every outbound SMS and POSTs the result as the
// request body to courier.channels[sms].request_config.url (the sms-sink in dev;
// a real gateway like Twilio in prod — there the template maps to the provider's
// API shape). `ctx` carries the message: `ctx.recipient` (the phone number) and
// `ctx.body` (the rendered SMS text, e.g. the verification/login code).
function(ctx) {
  to: ctx.recipient,
  body: ctx.body,
}
