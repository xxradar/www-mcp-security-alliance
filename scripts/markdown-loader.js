// Simple markdown to HTML converter
function convertMarkdownToHTML(markdown) {
    return markdown
        .replace(/^### (.*$)/gm, '<h4>$1</h4>')
        .replace(/^## (.*$)/gm, '<h3>$1</h3>')
        .replace(/^# (.*$)/gm, '<h2>$1</h2>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/```[\s\S]*?```/g, function(match) {
            const code = match.slice(3, -3);
            return '<pre><code>' + code + '</code></pre>';
        })
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>')
        .replace(/^(.*)$/gm, '<p>$1</p>')
        .replace(/<p><\/p>/g, '')
        .replace(/^<p>(<h[1-4]>.*<\/h[1-4]>)<\/p>$/gm, '$1')
        .replace(/^<p>(<pre><code>[\s\S]*?<\/code><\/pre>)<\/p>$/gm, '$1');
}

// Load markdown files from a directory
async function loadMarkdownFiles(directory) {
    const contentDiv = document.getElementById('markdown-content');
    
    if (!contentDiv) {
        console.error('markdown-content div not found');
        return;
    }
    
    // Known markdown files for each directory
    const directoryFiles = {
        'vulnerabilities': ['sql-injection.md'],
        'security': ['authentication.md'],
        'attacks': ['prompt-injection.md'],
        'resources': ['security-tools.md'],
        'contribute': ['README.md']
    };
    
    // Also check for common filenames
    const commonFiles = [
        'README.md',
        'index.md',
        'overview.md',
        'introduction.md',
        'guide.md'
    ];
    
    // Combine directory-specific files with common files
    const filesToCheck = [
        ...(directoryFiles[directory] || []),
        ...commonFiles
    ];
    
    // Remove duplicates
    const uniqueFiles = [...new Set(filesToCheck)];
    
    console.log(`Loading markdown files for directory: ${directory}`);
    console.log(`Files to check:`, uniqueFiles);
    
    let hasContent = false;
    
    for (const file of uniqueFiles) {
        try {
            const url = `${directory}/${file}`;
            console.log(`Attempting to fetch: ${url}`);
            
            const response = await fetch(url);
            console.log(`Response for ${file}:`, response.status, response.statusText);
            
            if (response.ok) {
                const markdown = await response.text();
                console.log(`Loaded ${file}, content length:`, markdown.length);
                
                const html = convertMarkdownToHTML(markdown);
                
                const fileDiv = document.createElement('div');
                fileDiv.className = 'markdown-file';
                fileDiv.innerHTML = `
                    <h5>📄 ${file}</h5>
                    ${html}
                `;
                
                contentDiv.appendChild(fileDiv);
                hasContent = true;
            }
        } catch (error) {
            console.error(`Error loading ${file}:`, error);
            continue;
        }
    }
    
    if (!hasContent) {
        console.log('No content loaded, showing placeholder');
        contentDiv.innerHTML = `
            <div class="alert info">
                <strong>📝 Content Coming Soon:</strong> Markdown files will be loaded from the <code>${directory}/</code> directory.
                <br>Add your <code>.md</code> files to contribute content to this section.
                <br><small>Debug: Attempted to load files: ${uniqueFiles.join(', ')}</small>
            </div>
        `;
    } else {
        console.log('Successfully loaded markdown content');
    }
}

// Initialize markdown loading when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // This will be called by individual pages
    console.log('DOM loaded, markdown loader ready');
});