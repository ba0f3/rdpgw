# Enforce clipboard and drive restrictions on destination hosts

The gateway advertises redirection policy in `.rdp` files and tunnel responses.
It forwards the RDP payload without decrypting or filtering its virtual channels.
A client that ignores those flags can use any redirection allowed by the
destination host. Host ACLs and gateway authentication still apply.

## Configure Windows session hosts

1. Open the Group Policy settings for the target session hosts under
   `Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection`.
2. Enable `Do not allow drive redirection` to block redirected drives and
   folders. Microsoft documents the applicable precedence and clipboard file
   transfer effect in its
   [drive redirection configuration](https://learn.microsoft.com/en-us/azure/virtual-desktop/redirection-configure-drives-storage).
3. Enable `Do not allow Clipboard redirection` to block clipboard content.
   Check the applicable settings for the Windows version in Microsoft's
   [clipboard redirection configuration](https://learn.microsoft.com/en-us/azure/virtual-desktop/redirection-configure-clipboard).
4. Apply the policies, verify effective policy on each destination, and restart
   the host or sessions where the platform requires it. Restricted users must
   not have permission to change these policies.

If different groups need different restrictions and the session host cannot
enforce them per session, separate destination host pools and restrict access
with gateway host ACLs. For xrdp or another RDP server, configure its equivalent
server-side channel restrictions and test the actual deployed version.

## Test the effective restrictions

Use fresh sessions for each supported client and destination combination.

- Enable drive redirection in the client and edit `.rdp` properties to permit
  it. Verify redirected folders and drives remain unavailable.
- Try text, image and file clipboard transfers in both directions. Verify the
  data types your policy prohibits do not transfer.
- Use a lab client that ignores gateway restriction flags. Verify the host
  restrictions still block clipboard and drive transfers.
- Confirm allowed host access and normal desktop authentication still work.

The gateway repository's opaque forwarding tests cannot substitute for these
client and host tests. They require a Windows or xrdp lab and effective host
policy evidence.
