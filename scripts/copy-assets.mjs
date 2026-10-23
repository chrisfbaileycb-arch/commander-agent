// tsc does not copy non-TS assets; the HUD and the soul file ship beside the compiled output.
import { cpSync, mkdirSync } from 'node:fs';

mkdirSync('dist/hud', { recursive: true });
cpSync('src/hud', 'dist/hud', { recursive: true });
cpSync('COMMANDER_SOUL.md', 'dist/COMMANDER_SOUL.md');
