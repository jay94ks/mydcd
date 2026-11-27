// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { internalAddress, suggestGatewayAddresses } from './ingress';

const a = (iface: string, address: string, scope: string) => ({ iface, address, cidr: `${address}/24`, scope });

describe('suggestGatewayAddresses', () => {
  it('takes the first public and the first private that is not sfcli or docker', () => {
    const list = [a('eth0', '203.0.113.21', 'public'), a('docker0', '172.17.0.1', 'private'), a('sfc0', '10.254.240.11', 'private'), a('eth1', '192.168.1.101', 'private'), a('lo', '127.0.0.1', 'loopback')];
    expect(suggestGatewayAddresses(list)).toEqual({ external: '203.0.113.21', local: '192.168.1.101' });
  });
  it('suggests nothing from an empty list', () => {
    expect(suggestGatewayAddresses([])).toEqual({ external: undefined, local: undefined });
  });
  it('treats the server IP range as internal, but not other 10.254 addresses', () => {
    expect(internalAddress(a('eth9', '10.254.255.3', 'private'))).toBe(true);
    expect(internalAddress(a('eth9', '10.254.1.3', 'private'))).toBe(false);
  });
});
