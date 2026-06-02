import { readdirSync, statSync, existsSync } from 'node:fs'
import { readdir, stat } from 'node:fs/promises'
import path from 'node:path'

export const DEFAULT_VIDEO_EXTENSIONS = new Set([
  '.mkv', '.mp4', '.m4v', '.avi', '.mov', '.webm',
  '.ts', '.m2ts', '.mpg', '.mpeg', '.wmv', '.flv', '.vob',
])

// Quality/release tags that appear in filenames but are not part of the title.
const NOISE = /\b(1080p|720p|480p|2160p|4k|uhd|bluray|blu-ray|bdrip|brrip|web-dl|webdl|webrip|hdtv|dvdrip|dvd|xvid|x264|x265|h264|h265|hevc|avc|aac|ac3|dts|truehd|atmos|remux|repack|proper|extended|theatrical|unrated|directors|cut|hdr|hdr10|hdr10plus|dolby|vision|sdr|amzn|nf|hmax|dsnp|pcm|flac|yify|yts|rarbg|eztv|sample)\b/gi

export interface ParsedMedia {
  title: string
  year: number | null
  kind: 'movie' | 'series' | 'unknown'
  season: number | null
  episode: number | null
}

export interface ScannedFile {
  path: string
  size_bytes: number
  ext: string
  parsed: ParsedMedia
  already_ingested?: boolean
  local_artwork?: string | null  // absolute path to a sibling poster/folder image
}

export function parseMediaPath(filePath: string): ParsedMedia {
  const ext = path.extname(filePath)
  const basename = path.basename(filePath, ext)
  const parentDir = path.basename(path.dirname(filePath))

  // ── Plex standard series: "Series Title - s01e01 - Episode Title"
  // ── Plex multi-episode:   "Series Title - s01e01-e03 - Episode Title"
  // Check BEFORE dot-normalization so Plex's proper-cased titles are preserved.
  const plexSeries = basename.match(/^(.+?)\s+-\s+[Ss](\d{1,2})[Ee](\d{1,2})(?:-[Ee]\d{1,2})?(?:\s+-\s+.*)?$/)
  if (plexSeries) {
    return {
      title: plexSeries[1].trim(),
      year: null,
      kind: 'series',
      season: parseInt(plexSeries[2], 10),
      episode: parseInt(plexSeries[3], 10),
    }
  }

  // ── Plex daily: "Series Title - 2013-10-30 - Episode Title"
  const plexDaily = basename.match(/^(.+?)\s+-\s+(\d{4})-\d{2}-\d{2}(?:\s+-\s+.*)?$/)
  if (plexDaily) {
    return {
      title: plexDaily[1].trim(),
      year: parseInt(plexDaily[2], 10),
      kind: 'series',
      season: null,
      episode: null,
    }
  }

  // ── Normalize separators for non-Plex files (dots/underscores → spaces)
  let name = basename.replace(/[._]+/g, ' ').trim()

  // ── Generic SxxExx (e.g. dot-separated: Show.Name.S01E01.mkv)
  const tvMatch = name.match(/^(.*?)\s*[Ss](\d{1,2})[Ee](\d{1,2})/i)
  if (tvMatch) {
    let rawTitle = tvMatch[1].replace(/[-\s]+$/, '').trim()
    if (!rawTitle) {
      rawTitle = parentDir.replace(/[._]+/g, ' ').replace(/\bSeason\s*\d+\b/i, '').trim()
    }
    return {
      title: cleanTitle(rawTitle) || rawTitle || basename,
      year: null,
      kind: 'series',
      season: parseInt(tvMatch[2], 10),
      episode: parseInt(tvMatch[3], 10),
    }
  }

  // ── Movie: year in parens — Plex standard "Movie Title (Year)"
  let year: number | null = null
  let titlePart = name

  const parenYear = name.match(/\(((19|20)\d{2})\)/)
  if (parenYear) {
    year = parseInt(parenYear[1], 10)
    titlePart = name.slice(0, parenYear.index!).trim()
  } else {
    const bareYear = name.match(/(?<!\d)((19|20)\d{2})(?!\d)/)
    if (bareYear) {
      year = parseInt(bareYear[1], 10)
      titlePart = name.slice(0, bareYear.index!).trim()
    }
  }

  return {
    title: cleanTitle(titlePart) || cleanTitle(name) || basename,
    year,
    kind: year ? 'movie' : 'unknown',
    season: null,
    episode: null,
  }
}

function cleanTitle(s: string): string {
  return s
    .replace(NOISE, ' ')
    .replace(/\s+/g, ' ')
    .replace(/[-–:,]+$/, '')
    .trim()
}

const IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp']

function findLocalArtwork(filePath: string, title: string): string | null {
  const dir = path.dirname(filePath)
  const safeTitle = title.replace(/[<>:"/\\|?*]/g, '').trim()
  const basenames = ['poster', 'folder', safeTitle]
  for (const base of basenames) {
    for (const ext of IMAGE_EXTENSIONS) {
      const candidate = path.join(dir, base + ext)
      if (existsSync(candidate)) return candidate
    }
  }
  return null
}

export function scanVideoFiles(
  dir: string,
  extensions: Set<string> = DEFAULT_VIDEO_EXTENSIONS,
): ScannedFile[] {
  const results: ScannedFile[] = []

  function walk(current: string) {
    let entries: string[]
    try {
      entries = readdirSync(current)
    } catch {
      return
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry)
      let st
      try {
        st = statSync(fullPath)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        walk(fullPath)
      } else if (st.isFile()) {
        const ext = path.extname(entry).toLowerCase()
        if (extensions.has(ext)) {
          const parsed = parseMediaPath(fullPath)
          results.push({
            path: fullPath,
            size_bytes: st.size,
            ext,
            parsed,
            local_artwork: findLocalArtwork(fullPath, parsed.title),
          })
        }
      }
    }
  }

  walk(dir)
  return results
}

// Async version for large/network-mounted libraries. Yields control between
// each directory so the event loop isn't blocked while waiting on NFS I/O.
// onFile fires for every discovered file — use it to stream results to a job
// object without waiting for the full scan to finish.
export async function scanVideoFilesAsync(
  dir: string,
  extensions: Set<string> = DEFAULT_VIDEO_EXTENSIONS,
  onProgress?: (found: number) => void,
  onFile?: (file: ScannedFile) => void,
): Promise<ScannedFile[]> {
  const results: ScannedFile[] = []

  async function walk(current: string) {
    let entries: string[]
    try {
      entries = await readdir(current)
    } catch {
      return
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry)
      let st
      try {
        st = await stat(fullPath)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        await walk(fullPath)
      } else if (st.isFile()) {
        const ext = path.extname(entry).toLowerCase()
        if (extensions.has(ext)) {
          const parsed = parseMediaPath(fullPath)
          const file: ScannedFile = { path: fullPath, size_bytes: st.size, ext, parsed, local_artwork: findLocalArtwork(fullPath, parsed.title) }
          results.push(file)
          onFile?.(file)
          if (onProgress && results.length % 50 === 0) onProgress(results.length)
        }
      }
    }
  }

  await walk(dir)
  return results
}
