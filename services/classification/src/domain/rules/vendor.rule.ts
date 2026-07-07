import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/** Maps a hardware vendor to likely device type(s). */
const VENDOR_MAP: { match: RegExp; votes: [DeviceType, number][] }[] = [
  { match: /raspberry pi/i, votes: [['computer', 0.4], ['iot', 0.3]] },
  { match: /espressif|esp/i, votes: [['iot', 0.7]] },
  { match: /sonos/i, votes: [['smart-speaker', 0.8]] },
  { match: /philips.*(hue|lighting)/i, votes: [['smart-home', 0.8]] },
  { match: /ubiquiti|cisco|meraki|netgear|tp-link|avm|compal|arris|technicolor|sagemcom|zyxel|huawei technolog/i, votes: [['router', 0.5], ['access-point', 0.3]] },
  { match: /brother|hewlett|hp inc/i, votes: [['printer', 0.8]] },
  { match: /sony|microsoft/i, votes: [['game-console', 0.4], ['computer', 0.2]] },
  { match: /amazon/i, votes: [['smart-speaker', 0.4], ['streaming-device', 0.3]] },
  { match: /google( nest)?/i, votes: [['smart-home', 0.4], ['streaming-device', 0.3]] },
  { match: /samsung/i, votes: [['phone', 0.3], ['tv', 0.3]] },
  { match: /apple/i, votes: [['phone', 0.25], ['computer', 0.25]] },
  { match: /intel/i, votes: [['computer', 0.3]] },
];

export class VendorRule implements ClassificationRule {
  readonly name = 'vendor';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    if (!input.vendor) return [];
    const entry = VENDOR_MAP.find((v) => v.match.test(input.vendor!));
    if (!entry) return [];
    return entry.votes.map(([deviceType, weight]) => ({
      deviceType,
      weight,
      reason: `vendor "${input.vendor}"`,
    }));
  }
}
