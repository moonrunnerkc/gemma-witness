<script lang="ts" module>
  export type IconName =
    | "mic"
    | "stop"
    | "image"
    | "sparkles"
    | "shield"
    | "check"
    | "alert"
    | "arrow-right"
    | "copy"
    | "folder"
    | "key"
    | "circle";
</script>

<script lang="ts">
  type Props = { name: IconName; size?: number };
  let { name, size = 16 }: Props = $props();
</script>

<svg
  xmlns="http://www.w3.org/2000/svg"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.75"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  {#if name === "mic"}
    <rect x="9" y="3" width="6" height="12" rx="3" />
    <path d="M5 11a7 7 0 0 0 14 0" />
    <path d="M12 18v3" />
  {:else if name === "stop"}
    <rect x="6" y="6" width="12" height="12" rx="1.5" />
  {:else if name === "image"}
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <circle cx="9" cy="10" r="1.5" />
    <path d="m21 16-5-5-9 9" />
  {:else if name === "sparkles"}
    <path d="M12 3v4M12 17v4M3 12h4M17 12h4" />
    <path d="m6.3 6.3 2.4 2.4M15.3 15.3l2.4 2.4M6.3 17.7l2.4-2.4M15.3 8.7l2.4-2.4" />
  {:else if name === "shield"}
    <path d="M12 3 4 6v6c0 5 3.5 8.5 8 9 4.5-.5 8-4 8-9V6l-8-3Z" />
    <path d="m9 12 2 2 4-4" />
  {:else if name === "check"}
    <path d="m5 12 5 5 9-11" />
  {:else if name === "alert"}
    <path d="M12 3 2 20h20L12 3Z" />
    <path d="M12 10v4M12 17h.01" />
  {:else if name === "arrow-right"}
    <path d="M5 12h14M13 5l7 7-7 7" />
  {:else if name === "copy"}
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
  {:else if name === "folder"}
    <path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
  {:else if name === "key"}
    <circle cx="8" cy="14" r="4" />
    <path d="m11 11 9-9M16 6l3 3" />
  {:else if name === "circle"}
    <circle cx="12" cy="12" r="5" fill="currentColor" stroke="none" />
  {/if}
</svg>
