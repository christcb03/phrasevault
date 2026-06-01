import { readdirSync, statSync } from 'node:fs'
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
}

export function parseMediaPath(filePath: string): ParsedMedia {
  const ext = path.extname(filePath)
  const basename = path.basename(filePath, ext)
  const parentDir = path.basename(path.dirname(filePath))

  // Normalize separators; keep parens for year detection
  let name = basename.replace(/[._]+/g, ' ').trim()

  // TV: SxxExx anywhere in name
  const tvMatch = name.match(/^(.*?)\s*[Ss](\d{1,2})[Ee](\d{1,2})/i)
  if (tvMatch) {
    let rawTitle = tvMatch[1].trim()
    // If the filename starts with SxxExx the title is in the parent dir
    if (!rawTitle) {
      rawTitle = parentDir
        .replace(/[._]+/g, ' ')
        .replace(/\bSeason\s*\d+\b/i, '')
        .trim()
    }
    return {
      title: cleanTitle(rawTitle) || rawTitle || basename,
      year: null,
      kind: 'series',
      season: parseInt(tvMatch[2], 10),
      episode: parseInt(tvMatch[3], 10),
    }
  }

  // Year in parens: "Title (2019)"
  let year: number | null = null
  let titlePart = name

  const parenYear = name.match(/\(((19|20)\d{2})\)/)
  if (parenYear) {
    year = parseInt(parenYear[1], 10)
    titlePart = name.slice(0, parenYear.index!).trim()
  } else {
    // Bare year surrounded by word boundaries
    const bareYear = name.match(/(?<!\d)((19|20)\d{2})(?!\d)/)
    if (bareYear) {
      year = parseInt(bareYear[1], 10)
      titlePart = name.slice(0, bareYear.index!).trim()
    }
  }

  const title = cleanTitle(titlePart) || cleanTitle(name) || basename

  return {
    title,
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
          results.push({
            path: fullPath,
            size_bytes: st.size,
            ext,
            parsed: parseMediaPath(fullPath),
          })
        }
      }
    }
  }

  walk(dir)
  return results
}
