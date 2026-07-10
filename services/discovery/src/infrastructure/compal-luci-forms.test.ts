import { describe, expect, it } from 'vitest';
import { buildCompalMeshForm, buildCompalRebootForm, parseCompalMeshEnabled } from './compal-luci-forms.js';

describe('parseCompalMeshEnabled', () => {
  it('detects checked mesh checkbox', () => {
    const html = '<input type="checkbox" name="cbid.meshwifi.basic.enable" value="1" checked="checked" />';
    expect(parseCompalMeshEnabled(html)).toBe(true);
  });

  it('detects unchecked mesh checkbox', () => {
    const html = '<input type="checkbox" name="cbid.meshwifi.basic.enable" value="1" />';
    expect(parseCompalMeshEnabled(html)).toBe(false);
  });
});

describe('buildCompalMeshForm', () => {
  it('includes enable field when turning mesh on', () => {
    const html =
      '<input name="cbi.cbe.meshwifi.basic.enable" value="1" />' +
      '<input type="checkbox" name="cbid.meshwifi.basic.enable" value="1" />' +
      '<input type="submit" name="cbi.apply" value="Salvar" />';
    const fields = buildCompalMeshForm(html, true);
    expect(fields['cbid.meshwifi.basic.enable']).toBe('1');
    expect(fields['cbi.cbe.meshwifi.basic.enable']).toBe('1');
    expect(fields['cbi.apply']).toBe('Salvar');
  });

  it('omits enable field when turning mesh off', () => {
    const html =
      '<input name="cbi.cbe.meshwifi.basic.enable" value="1" />' +
      '<input type="checkbox" name="cbid.meshwifi.basic.enable" value="1" checked="checked" />';
    const fields = buildCompalMeshForm(html, false);
    expect(fields['cbid.meshwifi.basic.enable']).toBeUndefined();
    expect(fields['cbi.cbe.meshwifi.basic.enable']).toBe('1');
  });
});

describe('buildCompalRebootForm', () => {
  it('uses reboot submit when present', () => {
    const html = '<input type="submit" name="reboot" value="Reiniciar" />';
    expect(buildCompalRebootForm(html)).toEqual({ 'cbi.submit': '1', reboot: 'Reiniciar' });
  });
});
